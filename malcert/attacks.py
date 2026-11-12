"""C1: gradient-based evasion attacks in the constrained feature space, plus a
group-transplant attack that matches the threat model of the group-ablation certificate."""
import torch
import torch.nn.functional as F


class Constraints:
    """Holds the threat-model tensors. constrained=False gives the classic unconstrained
    attacker used in most image-style papers (all 2,381 features, both directions, no domain).

    zlo / zhi are the NATURAL bounds of each feature in standardised space (Preprocessor.bounds();
    +-inf where there is none), not the training-set range used in draft v1."""

    def __init__(self, mutable, monotone, zlo, zhi, device, constrained=True):
        n = len(mutable)
        t = lambda a, dt: torch.as_tensor(a, dtype=dt, device=device)
        if constrained:
            self.mask, self.mono = t(mutable, torch.bool), t(monotone, torch.bool)
            self.zlo, self.zhi = t(zlo, torch.float32), t(zhi, torch.float32)
        else:
            self.mask = torch.ones(n, dtype=torch.bool, device=device)
            self.mono = torch.zeros(n, dtype=torch.bool, device=device)
            self.zlo = torch.full((n,), -float("inf"), device=device)
            self.zhi = torch.full((n,), float("inf"), device=device)

    def project(self, x0, x, eps):
        """Projection onto the same set as models.input_box, so attack and certificate agree."""
        d = (x - x0).clamp(-eps, eps)
        d = torch.where(self.mono, d.clamp(min=0), d)
        d = torch.where(self.mask, d, torch.zeros_like(d))
        x = x0 + d
        return torch.maximum(torch.minimum(x, torch.maximum(self.zhi, x0)), torch.minimum(self.zlo, x0))


def pgd(model, x, y, eps, C, steps=50, restarts=1, alpha=None):
    """L_inf PGD maximising the CE loss of the true label; steps=1 & no random start = FGSM."""
    model.eval()
    alpha = alpha if alpha is not None else 2.5 * eps / max(steps, 1)
    best = x.clone()
    fooled = torch.zeros(len(x), dtype=torch.bool, device=x.device)
    for r in range(restarts):
        xa = x.clone() if steps == 1 else C.project(x, x + torch.empty_like(x).uniform_(-eps, eps), eps)
        for _ in range(steps):
            xa.requires_grad_(True)
            loss = F.cross_entropy(model(xa), y)
            g, = torch.autograd.grad(loss, xa)
            step = eps if steps == 1 else alpha
            xa = C.project(x, xa.detach() + step * g.sign(), eps)
        with torch.no_grad():
            f = model(xa).argmax(1) != y
        upd = f & ~fooled
        best[upd] = xa[upd]
        fooled |= f
    return best.detach(), fooled


def group_transplant(score_fn, x, donors, gid, mutable_groups, max_r):
    """Greedy L0-over-groups attack: copy whole feature groups from benign donors into a
    malware sample, picking at each step the (group, donor) that lowers the malware score most.
    score_fn(X) -> P(malware) or a malware vote fraction, shape (N,).
    Returns, for r = 0..max_r, whether the sample is still detected (score >= 0.5)."""
    gid = torch.as_tensor(gid, device=x.device)
    cur = x.clone()
    used = set()
    detected = [bool(score_fn(cur[None])[0] >= 0.5)]
    for r in range(1, max_r + 1):
        best_s, best_x, best_g = None, None, None
        for g in mutable_groups:
            if g in used:
                continue
            m = gid == g
            cand = cur.unsqueeze(0).repeat(len(donors), 1)
            cand[:, m] = donors[:, m]
            s = score_fn(cand)
            j = int(s.argmin())
            if best_s is None or s[j] < best_s:
                best_s, best_x, best_g = float(s[j]), cand[j], g
        if best_x is None:
            detected.append(detected[-1]); continue
        cur, used = best_x, used | {best_g}
        detected.append(best_s >= 0.5)
    return detected
