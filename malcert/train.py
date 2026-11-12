"""Training routines: standard, Gaussian-noise (for smoothing), PGD adversarial training,
group-ablation, and IBP / CROWN-IBP certified training (C3, symmetric or malware-only)."""
import time
import torch
import torch.nn.functional as F
from .attacks import pgd
from .models import ibp, crown, input_box


def _batches(n, bs, device, gen):
    perm = torch.randperm(n, generator=gen).to(device)
    for a in range(0, n, bs):
        yield perm[a:a + bs]


def fit(model, Xtr, ytr, cfg, mode="clean", sigma=0.0, noise_mask=None, C=None, k=None,
        cert=None, epochs=None, lr=None, seed=0, log=print):
    """mode in {clean, gauss, pgd, ablation, ibp, crownibp}.
    cert = dict(eps, mask, mono, zmin, zmax, asym) for ibp/crownibp."""
    epochs = epochs or cfg.epochs
    lr = lr or cfg.lr
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=cfg.weight_decay)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, epochs)
    gen = torch.Generator().manual_seed(seed)
    n = len(Xtr)
    steps_per_epoch = (n + cfg.batch_size - 1) // cfg.batch_size
    t0 = time.time()
    for ep in range(epochs):
        model.train()
        tot = 0.0
        for it, idx in enumerate(_batches(n, cfg.batch_size, Xtr.device, gen)):
            x, y = Xtr[idx], ytr[idx]
            if mode == "clean":
                loss = F.cross_entropy(model(x), y)
            elif mode == "gauss":
                loss = F.cross_entropy(model(x + torch.randn_like(x) * sigma * noise_mask), y)
            elif mode == "pgd":       # Madry-style, half clean / half adversarial
                xa, _ = pgd(model, x, y, cfg.at_eps, C, steps=cfg.at_steps)
                model.train()
                loss = 0.5 * F.cross_entropy(model(x), y) + 0.5 * F.cross_entropy(model(xa), y)
            elif mode == "ablation":
                G = model.n_groups
                r = torch.rand(len(x), G, device=x.device)
                kth = r.topk(k, dim=1).indices
                gm = torch.zeros_like(r).scatter_(1, kth, 1.0)
                loss = F.cross_entropy(model(x, gm), y)
            elif mode in ("ibp", "crownibp"):
                # schedule: clean warm-up, then ramp eps (and kappa / beta) linearly
                prog = (ep - cfg.ibp_warmup + it / steps_per_epoch) / cfg.ibp_ramp
                prog = min(max(prog, 0.0), 1.0)
                eps = cert["eps"] * prog
                kappa = 1.0 - 0.5 * prog
                clean = F.cross_entropy(model(x), y, reduction="none")
                if eps > 0:
                    lo, hi = input_box(x, eps, cert["mask"], cert["mono"], cert["zmin"], cert["zmax"])
                    lb_ibp, pre = ibp(model, lo, hi, y)
                    if mode == "crownibp":
                        beta = 1.0 - prog
                        lb = beta * crown(model, lo, hi, y, pre) + (1 - beta) * lb_ibp if beta > 0 else lb_ibp
                    else:
                        lb = lb_ibp
                    rob = F.softplus(-lb)
                    if cert.get("asym"):     # robustness is only needed for malware
                        rob = torch.where(y == 1, rob, clean)
                    loss = (kappa * clean + (1 - kappa) * rob).mean()
                else:
                    loss = clean.mean()
            else:
                raise ValueError(mode)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 10.0)
            opt.step()
            tot += loss.item() * len(idx)
        sched.step()
        if ep == epochs - 1 or ep % 5 == 0:
            log(f"    [{mode}] epoch {ep + 1}/{epochs} loss {tot / n:.4f} ({time.time() - t0:.0f}s)")
    model.eval()
    return model
