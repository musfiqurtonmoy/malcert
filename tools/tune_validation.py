"""Validation tuning for every model (REVISION_PLAN 2i; grids and metrics in REVISION_LOG 2-17).

    python tools/tune_validation.py --split family --out results_tuning            # full grid (~45 min GPU)
    python tools/tune_validation.py --split family --smoke --out results_tuning_smoke   # 1 epoch, 1 grid point

Seed 0, family-disjoint split. Grouped 3-fold cross-validation over train + validation of that split (log 2-30):
families assigned to folds category by category; each grid point is trained on 2 folds and scored on the third,
three times, and ranked by the mean over folds. The test part is never transformed or used.
Writes <out>/<model>.csv (one row per grid point: fold means, per-fold accuracy, wall-clock) and <out>/chosen.json.
The chosen settings are frozen in config.py by hand, then committed, before Stage 3 (plan 2i).
"""
import argparse, itertools, json, os, sys, time, zlib
from dataclasses import replace
import numpy as np
import pandas as pd
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.attacks import Constraints                                                 # noqa: E402
from malcert.certify import ablation_certify_exact, ablation_view_votes, ceiling_r, votes_from_views   # noqa: E402
from malcert.config import get_config                                                    # noqa: E402
from malcert.data import Preprocessor, family_folds, load_subset, split_indices, threat_masks   # noqa: E402
from malcert.models import MLP, AblationNet, load_families                              # noqa: E402
from malcert.partitions import attackable, partition                                    # noqa: E402
from malcert.train import fit                                                            # noqa: E402
from run_all import family_report, fit_lgbm_views, lgbm_view_votes                       # noqa: E402

GRIDS = {
    "mlp": [dict(lr=lr, epochs=e) for lr in (1e-3, 3e-4) for e in (30, 60)],
    "lgbm_main": [dict(n_estimators=n, num_leaves=l) for n in (200, 500) for l in (31, 64)],
    "lgbm_second": [dict(n_estimators=n, num_leaves=l) for n in (200, 500) for l in (31, 64)],
    "abl_second_mlp": [dict(epochs=e) for e in (30, 60, 90)],
    "crown_unc": [dict(eps=e) for e in (0.05, 0.1)],
    "crown_box": [dict(eps=e) for e in (0.05, 0.1)],
    "crown_edit": [dict(t_train=t, agg=a) for t in (0.5, 1.0) for a in ("mean", "max")],
}
FPR_MAX = 0.01


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="family", choices=["random", "family"])
    ap.add_argument("--out", default="results_tuning")
    ap.add_argument("--models", default=",".join(GRIDS))
    ap.add_argument("--smoke", action="store_true", help="1 epoch and the first grid point of every model")
    a = ap.parse_args()
    os.chdir(ROOT)
    os.makedirs(a.out, exist_ok=True)
    cfg = get_config("full", split=a.split)                     # full-preset budgets, as in Stage 3
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=0)
    pool = np.concatenate([sp["tr"], sp["va"]])                  # train + validation; the test part is not used
    folds = family_folds(data["y"], data["family"], data["category"], pool, 3, 0)    # grouped 3-fold CV (log 2-30)
    X_all, y_all = data["X"], data["y"]
    del data
    mutable, monotone = threat_masks()
    fp = pd.read_csv(os.path.join("ps_results", "grouping_footprint.csv"))
    if a.smoke:
        cfg = replace(cfg, epochs=1, ibp_epochs=1, ibp_warmup=0, ibp_ramp=1)
    T = lambda v, dt=torch.float32: torch.as_tensor(v, dtype=dt, device=dev)

    def fold_ctx(i):
        """Training = the other two folds, evaluation = fold i; standardisation fitted on the training folds."""
        tr = np.concatenate([folds[j] for j in range(3) if j != i]); ev = folds[i]
        pp = Preprocessor().fit(X_all[tr])
        zlo, zhi = pp.bounds()
        return dict(Xtr=T(pp.transform(X_all[tr])), ytr=T(y_all[tr], torch.long), Xva=T(pp.transform(X_all[ev])),
                    yv=y_all[ev], Xtr_raw=X_all[tr], Xva_raw=X_all[ev], ytr_np=y_all[tr],
                    Ccon=Constraints(mutable, monotone, zlo, zhi, dev, constrained=True),
                    Cunc=Constraints(mutable, monotone, zlo, zhi, dev, constrained=False),
                    fams=load_families(pp.sd, dev))

    def run(model, p, c):
        Xtr, ytr, Xva, yv, fams, Ccon, Cunc = c["Xtr"], c["ytr"], c["Xva"], c["yv"], c["fams"], c["Ccon"], c["Cunc"]
        mal, d = yv == 1, Xtr.shape[1]

        def clean(pred):
            return dict(val_acc=float((pred == yv).mean()), val_tpr=float(pred[mal].mean()), val_fpr=float(pred[~mal].mean()))

        def group_metric(vm, part, k):
            gid, names = partition(part)
            att = attackable(gid)
            subs = [tuple(s) for s in itertools.combinations(range(len(names)), k)]
            ex = ablation_certify_exact(vm, torch.as_tensor(yv, device=vm.device), subs, att, len(att))
            cs = []
            for row in fp[fp.partition == part].itertuples():
                ok = row.r_needed <= min(ceiling_r(len(names), k), len(att))
                cs.append(float(ex[mal, row.r_needed].mean()) if ok else 0.0)
            votes = votes_from_views(vm)
            return dict(clean((votes[:, 1] >= votes[:, 0]).long().cpu().numpy()), cert=float(np.mean(cs)))

        def crown_metric(m):
            with torch.no_grad():
                pred = m(Xva).argmax(1).cpu().numpy()
            fr = family_report(m, Xva, yv, fams, (1.0,), Ccon.zlo, Ccon.zhi, dev)
            return dict(clean(pred), cert=fr["mean_over_families_t1"], **{f"cert_{f}": fr[f][0] for f in fams})

        torch.manual_seed(zlib.crc32(f"{model}|{sorted(p.items())}".encode()))
        t0 = time.time()
        if model == "mlp":
            m = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, replace(cfg, lr=p["lr"]), "clean",
                    epochs=1 if a.smoke else p["epochs"], seed=0, log=lambda s: None)
            with torch.no_grad():
                out = clean(m(Xva).argmax(1).cpu().numpy())
        elif model.startswith("lgbm_"):
            _, part, k, _ = cfg.ablation_configs[0 if model == "lgbm_main" else 1]
            gid, _ = partition(part)
            _, views = fit_lgbm_views(c["Xtr_raw"], c["ytr_np"], gid, k, p["n_estimators"], p["num_leaves"], 0)
            out = group_metric(lgbm_view_votes(views, c["Xva_raw"]), part, k)
        elif model == "abl_second_mlp":
            _, part, k, _ = cfg.ablation_configs[1]
            gid, names = partition(part)
            net = fit(AblationNet(d, len(names), gid, cfg.hidden).to(dev), Xtr, ytr, cfg, "ablation", k=k,
                      epochs=1 if a.smoke else p["epochs"], seed=0, log=lambda s: None)
            out = group_metric(ablation_view_votes(net, Xva, k), part, k)
        else:
            if model == "crown_edit":
                cert = dict(families=fams, t_train=p["t_train"], agg=p["agg"], zlo=Ccon.zlo, zhi=Ccon.zhi)
            else:
                C = Cunc if model == "crown_unc" else Ccon
                cert = dict(eps=p["eps"], mask=C.mask, mono=C.mono, zlo=C.zlo, zhi=C.zhi, asym=False)
            m = fit(MLP(d, cfg.ibp_hidden).to(dev), Xtr, ytr, cfg, "crownibp", cert=cert, epochs=cfg.ibp_epochs,
                    seed=0, log=lambda s: None)
            out = crown_metric(m)
        out["seconds"] = round(time.time() - t0, 1)
        out["seconds_per_epoch"] = round(out["seconds"] / (1 if a.smoke else p.get("epochs", cfg.ibp_epochs)), 1) \
            if not model.startswith("lgbm_") else None
        return out

    ctxs = [fold_ctx(i) for i in range(3)]
    print("folds (malware / benign):", [(int((y_all[f] == 1).sum()), int((y_all[f] == 0).sum())) for f in folds], flush=True)
    chosen = {}
    for model in a.models.split(","):
        rows = []
        for p in GRIDS[model][:1] if a.smoke else GRIDS[model]:
            per = [run(model, p, c) for c in ctxs]                 # one score per fold
            r = dict(p, **{k: float(np.mean([o[k] for o in per])) for k in per[0]
                           if per[0][k] is not None and k != "seconds"},
                     val_acc_folds=[round(o["val_acc"], 4) for o in per],
                     seconds=round(sum(o["seconds"] for o in per), 1))         # total over the 3 folds
            rows.append(r)
            print(model, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()}, flush=True)
        D = pd.DataFrame(rows)
        D.to_csv(os.path.join(a.out, f"{model}.csv"), index=False)
        if model == "mlp":
            best = D.sort_values("val_acc", ascending=False).iloc[0]
        else:
            ok = D[D.val_fpr <= FPR_MAX]
            best = (ok.sort_values("cert", ascending=False) if len(ok) else D.sort_values("val_fpr")).iloc[0]
        chosen[model] = {k: (v.item() if hasattr(v, "item") else v) for k, v in best.items() if k in GRIDS[model][0]}
    json.dump(dict(chosen=chosen, split=a.split, smoke=a.smoke, fpr_max=FPR_MAX), open(os.path.join(a.out, "chosen.json"), "w"),
              indent=1)
    print("chosen:", chosen)


if __name__ == "__main__":
    main()
