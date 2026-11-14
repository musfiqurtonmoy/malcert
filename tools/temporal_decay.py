"""Stage 3c: decay curves, update frequency and composition vs drift (REVISION_LOG 3-3; no training).

    python tools/temporal_decay.py --runs results_cut_2019-12 results_cut_2020-04 [--out results_temporal_decay]

Per run (cut-off) and seed: test months merged forward until each bin has >= 200 malware and >= 200 benign;
per bin: clean TPR / FPR of the saved models, certified detection (group ablation main and per-view LightGBM main
at r = 1, edit-aware CROWN-IBP mean over the four families at t = 1). Update frequency: months until certified
detection falls below 90% of its first-bin value. Composition vs drift (clean TPR): in-distribution per-category
TPR (training-period validation part) reweighted to each bin's category mix; composition effect = reweighted -
in-distribution, drift effect = observed - reweighted.
Writes <out>/decay.csv, <out>/update_frequency.csv, <out>/composition.csv.
"""
import argparse, glob, json, os
import numpy as np
import pandas as pd

MIN_N = 200
CLEAN = ["lightgbm", "mlp", "abl_main", "abl_lgbm_main"]
FAMS = ["F_content", "F_section", "F_import", "F_strip"]


def bins(months, y):
    """Merge consecutive months forward until both classes have >= MIN_N samples. Returns a label per sample."""
    ms = sorted(m for m in set(months) if m != "unknown")
    lab, cur, nm, nb = {}, [], 0, 0
    for m in ms:
        cur.append(m); sel = months == m
        nm += int((y[sel] == 1).sum()); nb += int((y[sel] == 0).sum())
        if nm >= MIN_N and nb >= MIN_N:
            for x in cur:
                lab[x] = cur[0] if len(cur) == 1 else f"{cur[0]}..{cur[-1]}"
            cur, nm, nb = [], 0, 0
    for x in cur:                                    # remainder joins the last complete bin
        lab[x] = list(lab.values())[-1] if lab else x
    return np.array([lab.get(m, "unknown") for m in months])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", default="results_temporal_decay")
    ap.add_argument("--paper", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paper"),
                    help="writes <paper>/tables/numbers_decay.tex; pass '' to skip")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows, comp = [], []
    for res in a.runs:
        cfg = json.load(open(os.path.join(res, "results.json")))["config"]
        for f in sorted(glob.glob(os.path.join(res, "samples_seed*.npz"))):
            S, seed = dict(np.load(f)), os.path.basename(f)[12:-4]
            y, cat, b = S["y"], S["category"], bins(S["month"], S["y"])
            vy, vc = S["val_y"], S["val_category"]
            for lab in sorted(set(b) - {"unknown"}):      # chronological: labels start with YYYY-MM
                m = b == lab
                r = dict(cutoff=cfg["cutoff"], seed=seed, bin=lab, n_malware=int((y[m] == 1).sum()), n_benign=int((y[m] == 0).sum()))
                for k in CLEAN:
                    if "pred_" + k in S:
                        p = S["pred_" + k][m]
                        r["tpr_" + k], r["fpr_" + k] = float(p[y[m] == 1].mean()), float(p[y[m] == 0].mean())
                mm = m & (y == 1)
                for k in ("abl_main", "abl_lgbm_main"):
                    if k + "_cert_exact" in S:
                        r["cert_r1_" + k] = float(S[k + "_cert_exact"][mm, 1].mean())
                fk = [f"ct_crownibp_edit_famcert_t1_{x}" for x in FAMS]
                if all(k in S for k in fk):
                    r["cert_t1_crown_edit"] = float(np.mean([S[k][mm].mean() for k in fk]))
                rows.append(r)
                # composition vs drift, clean TPR
                for k in CLEAN:
                    if "val_pred_" + k not in S or "pred_" + k not in S:
                        continue
                    vp = S["val_pred_" + k]
                    tpr_in = float(vp[vy == 1].mean())
                    by_cat = {c: float(vp[(vy == 1) & (vc == c)].mean()) for c in set(vc[vy == 1])}
                    cs, ns = np.unique(cat[mm], return_counts=True)
                    rew = float(sum(n * by_cat.get(c, tpr_in) for c, n in zip(cs, ns)) / ns.sum())
                    obs = r["tpr_" + k]
                    comp.append(dict(cutoff=cfg["cutoff"], seed=seed, bin=lab, model=k, tpr_in_distribution=tpr_in,
                                     tpr_reweighted=rew, tpr_observed=obs, composition_effect=rew - tpr_in, drift_effect=obs - rew))
    D, C = pd.DataFrame(rows), pd.DataFrame(comp)
    D.to_csv(os.path.join(a.out, "decay.csv"), index=False)
    C.to_csv(os.path.join(a.out, "composition.csv"), index=False)
    M = D.groupby(["cutoff", "bin"], sort=True).mean(numeric_only=True).reset_index()   # first bin = first test month
    upd = []
    for cut, g in M.groupby("cutoff", sort=False):
        for k in [c for c in g.columns if c.startswith("cert_")]:
            v = g[k].values
            below = np.where(v < 0.9 * v[0])[0]
            upd.append(dict(cutoff=cut, metric=k, first_bin=g.bin.iloc[0], first_value=float(v[0]),
                            bins_until_below_90pct=int(below[0]) if len(below) else None,
                            bin_where_below=g.bin.iloc[below[0]] if len(below) else "never"))
    U = pd.DataFrame(upd)
    U.to_csv(os.path.join(a.out, "update_frequency.csv"), index=False)
    # macros (numbers_decay.tex); cut-offs A and B in chronological order
    cuts = sorted(M.cutoff.unique())
    stem = {"cert_r1_abl_main": "AblMain", "cert_r1_abl_lgbm_main": "LgbmViews", "cert_t1_crown_edit": "Edit"}
    N = {f"TdCut{'AB'[i]}": c for i, c in enumerate(cuts)}
    if len(cuts) == 2:
        (ya, ma), (yb, mb) = (map(int, c.split("-")) for c in cuts)
        N["TdCutGapMonths"] = str(12 * (yb - ya) + mb - ma)
    for i, c in enumerate(cuts):
        for _, r in U[U.cutoff == c].iterrows():
            N[f"TdFirst{stem[r.metric]}{'AB'[i]}"] = f"{100 * r.first_value:.1f}"
    mo = U.bins_until_below_90pct.dropna()
    N["TdMonthsMin"], N["TdMonthsMax"] = f"{mo.min():.0f}", f"{mo.max():.0f}"
    if len(cuts) == 2:                     # retraining: later cut-off minus earlier one on the months both test
        A_, B_ = (M[M.cutoff == c].set_index("bin") for c in cuts)
        common = A_.index.intersection(B_.index)
        g = [100 * (B_.loc[common, k] - A_.loc[common, k]).mean() for k in stem]
        N["TdRetrainGainMin"], N["TdRetrainGainMax"] = f"{min(g):.0f}", f"{max(g):.0f}"
        N["TdNCommonMonths"] = str(len(common))
    Cm = C.groupby(["cutoff", "model"])[["composition_effect", "drift_effect"]].mean()
    N["TdDriftMin"], N["TdDriftMax"] = f"{100 * Cm.drift_effect.min():.1f}", f"{100 * Cm.drift_effect.max():.1f}"
    N["TdCompMin"], N["TdCompMax"] = f"{100 * Cm.composition_effect.min():.1f}", f"{100 * Cm.composition_effect.max():.1f}"
    if a.paper:
        with open(os.path.join(a.paper, "tables", "numbers_decay.tex"), "w") as f:
            f.write("% auto-generated by tools/temporal_decay.py -- do not edit by hand\n")
            for k, v in N.items():
                f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(M.to_string(index=False, float_format=lambda v: f"{v:.3f}"))
    print(U.to_string(index=False))


if __name__ == "__main__":
    main()
