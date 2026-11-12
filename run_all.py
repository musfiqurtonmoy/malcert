"""Run every experiment in the paper and save results/results.json + per-sample arrays.

    python run_all.py --preset quick      # ~1 h on CPU, 1 seed  (debug / first look)
    python run_all.py --preset full       # paper numbers, 3 seeds (GPU recommended)
"""
import argparse, json, os, time
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score, f1_score

from malcert.config import get_config
from malcert.data import (load_subset, split_indices, Preprocessor, threat_masks, group_ids,
                          GROUP_NAMES, IMMUTABLE_GROUPS)
from malcert.models import MLP, AblationNet, ibp, crown, input_box
from malcert.attacks import Constraints, pgd, group_transplant
from malcert.certify import ablation_votes, ablation_certify, smooth_certify
from malcert.train import fit


def metrics(y, pred, score=None):
    y, pred = np.asarray(y), np.asarray(pred)
    out = dict(acc=float((y == pred).mean()), f1=float(f1_score(y, pred)),
               tpr=float((pred[y == 1] == 1).mean()), fpr=float((pred[y == 0] == 1).mean()))
    if score is not None:
        out["auc"] = float(roc_auc_score(y, score))
    return out


@torch.no_grad()
def predict(model, X, bs=4096):
    P = torch.cat([F.softmax(model(X[a:a + bs]), 1)[:, 1] for a in range(0, len(X), bs)])
    return P.cpu().numpy()


def attack_curve(model, Xm, ym, cfg, C):
    """Robust detection rate (TPR) of malware under FGSM / PGD for each eps."""
    out = {}
    for name, steps in (("fgsm", 1), ("pgd", cfg.pgd_steps)):
        out[name] = []
        for eps in cfg.eps_list:
            det = []
            for a in range(0, len(Xm), 500):
                _, fooled = pgd(model, Xm[a:a + 500], ym[a:a + 500], eps, C, steps=steps,
                                restarts=cfg.pgd_restarts)
                det.append((~fooled).cpu().numpy())
            out[name].append(float(np.concatenate(det).mean()))
    return out


def verify(model, X, y, eps, C, bs=1024):
    """Sound certificate: margin lower bound > 0 under max(IBP, CROWN)."""
    res = []
    for a in range(0, len(X), bs):
        x, t = X[a:a + bs], y[a:a + bs]
        with torch.no_grad():
            lo, hi = input_box(x, eps, C.mask, C.mono, C.zmin, C.zmax)
            lb_i, pre = ibp(model, lo, hi, t)
            lb_c = crown(model, lo, hi, t, pre)
        res.append((torch.maximum(lb_i, lb_c) > 0).cpu().numpy())
    return np.concatenate(res)


def run_seed(cfg, seed, dev, log):
    torch.manual_seed(seed); np.random.seed(seed)
    R, S = {}, {}                                  # scalar results, per-sample arrays
    data = load_subset(cfg, seed=0)                # same 30K subset for every seed
    sp = split_indices(data, cfg, seed=seed)
    pp = Preprocessor().fit(data["X"][sp["tr"]])
    T = lambda a, dt=torch.float32: torch.as_tensor(a, dtype=dt, device=dev)
    Xtr, Xva, Xte = (T(pp.transform(data["X"][sp[k]])) for k in ("tr", "va", "te"))
    ytr, yva, yte = (T(data["y"][sp[k]], torch.long) for k in ("tr", "va", "te"))
    yte_np = data["y"][sp["te"]]
    S["y"], S["category"] = yte_np, np.asarray(data["category"][sp["te"]], dtype=str)
    mutable, monotone = threat_masks()
    gid = group_ids()
    Ccon = Constraints(mutable, monotone, pp.zmin, pp.zmax, dev, constrained=True)
    Cunc = Constraints(mutable, monotone, pp.zmin, pp.zmax, dev, constrained=False)
    d = Xtr.shape[1]
    R["data"] = dict(n_train=len(ytr), n_val=len(yva), n_test=len(yte),
                     n_mutable=int(mutable.sum()), n_monotone=int(monotone.sum()),
                     n_malware=int(data["y"].sum()), n_benign=int((data["y"] == 0).sum()),
                     n_categories=int(len(set(data["category"])) - 1),
                     n_families=int(len(set(data["family"])) - 1),
                     categories={c: int((data["category"] == c).sum()) for c in sorted(set(data["category"]))})
    log(f"seed {seed}: train {len(ytr)} / val {len(yva)} / test {len(yte)}; mutable dims {mutable.sum()}")

    # ---------------- baselines ----------------
    t0 = time.time()
    import lightgbm as lgb
    gbm = lgb.LGBMClassifier(n_estimators=500, num_leaves=64, learning_rate=0.05,
                             random_state=seed, verbose=-1)
    gbm.fit(data["X"][sp["tr"]], data["y"][sp["tr"]])
    s = gbm.predict_proba(data["X"][sp["te"]])[:, 1]
    R["lightgbm"] = metrics(yte_np, s >= 0.5, s)
    log(f"  LightGBM {R['lightgbm']}  ({time.time() - t0:.0f}s)")

    std = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "clean", seed=seed, log=log)
    s = predict(std, Xte); R["mlp"] = metrics(yte_np, s >= 0.5, s); log(f"  MLP {R['mlp']}")
    S["p_mlp"] = s

    # ---------------- C1: attacks ----------------
    mal = torch.where(yte == 1)[0][:cfg.n_attack_points]
    Xm, ym = Xte[mal], yte[mal]
    at = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "pgd", C=Ccon, seed=seed, log=log)
    s = predict(at, Xte); R["pgd_at"] = metrics(yte_np, s >= 0.5, s); log(f"  PGD-AT {R['pgd_at']}")
    R["attacks"] = {}
    for mname, m in (("mlp", std), ("pgd_at", at)):
        R["attacks"][mname] = {"constrained": attack_curve(m, Xm, ym, cfg, Ccon),
                               "unconstrained": attack_curve(m, Xm, ym, cfg, Cunc)}
        log(f"  attacks on {mname}: {R['attacks'][mname]}")

    # ---------------- C2a: group-ablation certificates ----------------
    G = len(GROUP_NAMES)
    mut_groups = [g for g, n in enumerate(GROUP_NAMES) if n not in IMMUTABLE_GROUPS]
    R["ablation"] = {}
    gm_idx = torch.where(yte == 1)[0][:cfg.group_attack_points]
    donors_pool = Xtr[ytr == 0]
    gen = torch.Generator().manual_seed(seed)
    donor_sets = [donors_pool[torch.randperm(len(donors_pool), generator=gen)[:cfg.group_attack_donors].to(dev)]
                  for _ in range(len(gm_idx))]

    def emp_curve(score_fn):
        rows = []
        for j, i in enumerate(gm_idx):
            det = group_transplant(score_fn, Xte[i], donor_sets[j], gid, mut_groups, cfg.group_attack_max_r)
            rows.append(np.cumprod(det).astype(bool))   # budget r allows any r' <= r
        return np.array(rows)

    std_emp = emp_curve(lambda Z: torch.as_tensor(predict(std, Z)))
    R["group_attack_mlp"] = std_emp.mean(0).tolist()
    log(f"  group-transplant on MLP, detection vs r: {R['group_attack_mlp']}")
    for k in cfg.keep_list:
        net = fit(AblationNet(d, G, gid, cfg.hidden).to(dev), Xtr, ytr, cfg, "ablation", k=k, seed=seed, log=log)
        votes = ablation_votes(net, Xte, k)
        pred = (votes[:, 1] >= votes[:, 0]).long().cpu().numpy()      # ties -> malware
        cert = ablation_certify(votes, yte, G, k, len(mut_groups))
        n_sub = len(net.subsets(k))
        emp = emp_curve(lambda Z: (ablation_votes(net, Z, k)[:, 1] / n_sub).cpu())
        cert_sub = cert[gm_idx.cpu().numpy()][:, :cfg.group_attack_max_r + 1]
        viol = int((cert_sub & ~emp).sum())
        R["ablation"][k] = dict(clean=metrics(yte_np, pred, (votes[:, 1] / n_sub).cpu().numpy()),
                                cert_tpr=cert[yte_np == 1].mean(0).tolist(),
                                cert_acc=cert.mean(0).tolist(),
                                empirical_tpr=emp.mean(0).tolist(), violations=viol, n_subsets=n_sub)
        S[f"abl{k}_cert"] = cert
        log(f"  ablation k={k}: {R['ablation'][k]}")

    # ---------------- C2b: randomized smoothing ----------------
    R["smoothing"] = {}
    pts = torch.arange(min(cfg.n_cert_points, len(Xte)), device=dev)
    masks = {"isotropic": torch.ones(d, device=dev),
             "subspace": torch.as_tensor(mutable, dtype=torch.float32, device=dev)}
    for sigma in cfg.sigmas:
        for vname, nm in masks.items():
            m = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "gauss", sigma=sigma, noise_mask=nm,
                    seed=seed, log=log)
            pr, rad = smooth_certify(m, Xte[pts], yte[pts], sigma, nm, cfg.n0, cfg.n_cert, cfg.alpha)
            yp = yte_np[:len(pts)]
            key = f"{vname}_{sigma}"
            R["smoothing"][key] = dict(sigma=sigma, variant=vname,
                                       clean_acc=float((pr == yp).mean()),
                                       abstain=float((pr == -1).mean()),
                                       tpr=float((pr[yp == 1] == 1).mean()))
            S[f"rs_{key}_pred"], S[f"rs_{key}_rad"] = pr, rad
            log(f"  smoothing {key}: {R['smoothing'][key]}")
    S["rs_y"] = yte_np[:len(pts)]

    # ---------------- C3: certified training ----------------
    R["certified_training"] = {}
    ctab = dict(eps=cfg.ibp_train_eps, mask=Ccon.mask, mono=Ccon.mono, zmin=Ccon.zmin, zmax=Ccon.zmax)
    variants = {
        "standard": dict(mode="clean"),
        "pgd_at": dict(mode="pgd", C=Ccon),
        "ibp": dict(mode="ibp", cert=dict(ctab, asym=False)),
        "crownibp": dict(mode="crownibp", cert=dict(ctab, asym=False)),
        "crownibp_asym": dict(mode="crownibp", cert=dict(ctab, asym=True)),
    }
    for vname, kw in variants.items():
        ep = cfg.ibp_epochs if "ibp" in vname else cfg.epochs
        m = fit(MLP(d, cfg.ibp_hidden).to(dev), Xtr, ytr, cfg, epochs=ep, seed=seed, log=log, **kw)
        s = predict(m, Xte)
        row = dict(clean=metrics(yte_np, s >= 0.5, s), cert_tpr=[], cert_acc=[], cert_tpr_unconstrained=[],
                   pgd_tpr=[], violations=0)
        for eps in cfg.cert_eps_list:
            c = verify(m, Xte, yte, eps, Ccon)
            cu = verify(m, Xte, yte, eps, Cunc)
            row["cert_tpr"].append(float(c[yte_np == 1].mean()))
            row["cert_acc"].append(float(c.mean()))
            row["cert_tpr_unconstrained"].append(float(cu[yte_np == 1].mean()))
            _, fooled = pgd(m, Xm, ym, eps, Ccon, steps=cfg.pgd_steps)
            fooled = fooled.cpu().numpy()
            row["pgd_tpr"].append(float((~fooled).mean()))
            row["violations"] += int((c[mal.cpu().numpy()] & fooled).sum())   # must stay 0
            if abs(eps - cfg.ibp_train_eps) < 1e-12:
                S[f"ct_{vname}_cert"] = c
        R["certified_training"][vname] = row
        log(f"  certified training {vname}: {row}")
    return R, S


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", default="quick", choices=["quick", "full"])
    ap.add_argument("--data_dir", default="data")
    ap.add_argument("--out_dir", default="results")
    ap.add_argument("--split", default="random", choices=["random", "temporal"])
    a = ap.parse_args()
    cfg = get_config(a.preset, out_dir=a.out_dir, split=a.split,
                     data_npz=os.path.join(a.data_dir, "bodmas.npz"),
                     meta_csv=os.path.join(a.data_dir, "bodmas_metadata.csv"),
                     cat_csv=os.path.join(a.data_dir, "bodmas_malware_category.csv"))
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu") if cfg.device == "auto" else torch.device(cfg.device)
    os.makedirs(cfg.out_dir, exist_ok=True)
    logf = open(os.path.join(cfg.out_dir, "log.txt"), "a")

    def log(msg):
        print(msg, flush=True); logf.write(msg + "\n"); logf.flush()

    log(f"=== preset {a.preset} | device {dev} | split {cfg.split} | {time.ctime()} ===")
    allR = {"config": {k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(cfg).items()}, "seeds": {}}
    for seed in cfg.seeds:
        R, S = run_seed(cfg, seed, dev, log)
        allR["seeds"][str(seed)] = R
        np.savez_compressed(os.path.join(cfg.out_dir, f"samples_seed{seed}.npz"), **S)
        with open(os.path.join(cfg.out_dir, "results.json"), "w") as f:
            json.dump(allR, f, indent=1)
    log("done")


if __name__ == "__main__":
    main()
