"""Stage 3a statistics and 3b near-duplicate sensitivity.

    python tools/stats.py --family results_family [results_family_s34 ...] [--random results_random] [--paper paper]

1. Per metric: mean, std and 95% t-interval over seeds (family split, and random split if given).
2. The six pre-registered comparisons (REVISION_LOG 3-1) on the family split: paired difference per seed,
   95% t-interval, paired t-test, Holm correction across the six.
3. Near-duplicate sensitivity (log 3-4): main metrics recomputed on the test set without near-twins
   (nearest training neighbour within L2 0.1), from the saved per-sample arrays.
Writes <family>/stats_summary.csv, stats_comparisons.csv, stats_neardup.csv and paper/tables/numbers_stats.tex.
"""
import argparse, glob, json, os
import numpy as np
import pandas as pd
from scipy import stats as st

EDIT9 = ["E1_overlay", "E2_strings", "E3_section", "E4_imports", "E5_timestamp", "E6_secnames", "E7_header",
         "E8_strip", "E10_hdrfields"]
NEAR = 0.1


def eps_index(R, eps=0.05):
    return R["config"]["cert_eps_list"].index(eps)


def metric_fns(R):
    i5 = eps_index(R)
    ab = lambda s, n: s["ablation"][n]
    ct = lambda s, v: s["certified_training"][v]
    by_edit = lambda s, n: float(np.mean([ab(s, n)["cert_by_edit"][e]["cert_tpr"] for e in EDIT9]))
    return {
        "acc_lightgbm": lambda s: s["lightgbm"]["acc"], "acc_lightgbm_mono": lambda s: s["lightgbm_mono"]["acc"],
        "acc_mlp": lambda s: s["mlp"]["acc"], "acc_pgd_at": lambda s: s["pgd_at"]["acc"],
        "acc_abl_main": lambda s: ab(s, "main")["clean"]["acc"], "acc_abl_second": lambda s: ab(s, "second")["clean"]["acc"],
        "acc_abl_lgbm_main": lambda s: ab(s, "lgbm_main")["clean"]["acc"],
        "fpr_abl_lgbm_main": lambda s: ab(s, "lgbm_main")["clean"]["fpr"],
        "cert_r1_abl_main": lambda s: ab(s, "main")["cert_tpr_exact"][1],
        "cert_r1_abl_lgbm_main": lambda s: ab(s, "lgbm_main")["cert_tpr_exact"][1],
        "cert_edits_abl_main": lambda s: by_edit(s, "main"), "cert_edits_abl_second": lambda s: by_edit(s, "second"),
        "cert_edits_abl_ember": lambda s: by_edit(s, "ember"), "cert_edits_abl_lgbm_main": lambda s: by_edit(s, "lgbm_main"),
        "gattack_r1_lightgbm": lambda s: s["group_attack"]["lightgbm"][1],
        "gattack_r1_abl_lgbm_main": lambda s: s["group_attack"]["ablation_lgbm_main"][1],
        "certT1_crown_edit": lambda s: ct(s, "crownibp_edit")["family_cert"]["mean_over_families_t1"],
        "certT1_crown_unc": lambda s: ct(s, "crownibp_unc")["family_cert"]["mean_over_families_t1"],
        "certT1_crown_box": lambda s: ct(s, "crownibp")["family_cert"]["mean_over_families_t1"],
        "cert005_crown_box": lambda s: ct(s, "crownibp")["cert_tpr"][i5],
        "cert005_crown_unc": lambda s: ct(s, "crownibp_unc")["cert_tpr"][i5],
        "acc_crown_edit": lambda s: ct(s, "crownibp_edit")["clean"]["acc"],
        "fpr_crown_edit": lambda s: ct(s, "crownibp_edit")["clean"]["fpr"],
    }


MACRO = {  # metric -> macro stem (LaTeX macro names cannot hold digits)
    "acc_lightgbm": "AccLgbm", "acc_lightgbm_mono": "AccLgbmMono", "acc_mlp": "AccMlp", "acc_pgd_at": "AccPgdAt",
    "acc_abl_main": "AccAblMain", "acc_abl_second": "AccAblSecond", "acc_abl_lgbm_main": "AccLgbmViews",
    "fpr_abl_lgbm_main": "FprLgbmViews", "cert_r1_abl_main": "CertROneAblMain",
    "cert_r1_abl_lgbm_main": "CertROneLgbmViews", "cert_edits_abl_main": "CertEditsAblMain",
    "cert_edits_abl_second": "CertEditsAblSecond", "cert_edits_abl_ember": "CertEditsEmber",
    "cert_edits_abl_lgbm_main": "CertEditsLgbmViews", "gattack_r1_lightgbm": "GattackLgbm",
    "gattack_r1_abl_lgbm_main": "GattackLgbmViews", "certT1_crown_edit": "CertTOneEdit",
    "certT1_crown_unc": "CertTOneUnif", "certT1_crown_box": "CertTOneBox", "cert005_crown_box": "CertTrainEpsBox",
    "cert005_crown_unc": "CertTrainEpsUnif", "acc_crown_edit": "AccEdit", "fpr_crown_edit": "FprEdit",
}

COMPARISONS = [  # (label, metric A, metric B): difference A - B   (log 3-1)
    ("C1 edit-aware vs uniform CROWN-IBP, cert over T_f(1)", "certT1_crown_edit", "certT1_crown_unc"),
    ("C2 box vs uniform CROWN-IBP, cert at eps 0.05", "cert005_crown_box", "cert005_crown_unc"),
    ("C3 aligned5 k=2 vs EMBER k=1, cert over 9 edit types", "cert_edits_abl_main", "cert_edits_abl_ember"),
    ("C4 LightGBM views vs MLP views (main), cert at r=1", "cert_r1_abl_lgbm_main", "cert_r1_abl_main"),
    ("C5 LightGBM views vs LightGBM, group attack r=1", "gattack_r1_abl_lgbm_main", "gattack_r1_lightgbm"),
    ("C6 LightGBM views vs LightGBM, clean accuracy", "acc_abl_lgbm_main", "acc_lightgbm"),
]


def tint(x):
    x = np.asarray(x, float)
    n, m = len(x), x.mean()
    if n < 2:
        return m, 0.0, m, m
    s = x.std(ddof=1)
    h = st.t.ppf(0.975, n - 1) * s / np.sqrt(n)
    return m, s, m - h, m + h


def per_seed(folders):
    """Per-seed metrics from one or more results folders of the same experiment (same configuration apart from
    seeds and out_dir, same code SHA-256); a seed may appear in only one folder."""
    rows, ref = {}, None
    for res in folders:
        R = json.load(open(os.path.join(res, "results.json")))
        cfg = {k: v for k, v in R["config"].items() if k not in ("seeds", "out_dir", "device")}
        shas = {p.get("code_sha256") for p in R.get("provenance", [])}
        if ref is None:
            ref = (cfg, shas, res)
        elif cfg != ref[0] or shas != ref[1]:
            raise SystemExit(f"{res} differs from {ref[2]} in configuration or code; cannot pool their seeds")
        fns = metric_fns(R)
        for seed, s in sorted(R["seeds"].items(), key=lambda kv: int(kv[0])):
            if int(seed) in rows:
                raise SystemExit(f"seed {seed} appears in more than one folder")
            rows[int(seed)] = {k: (f(s) if _ok(f, s) else np.nan) for k, f in fns.items()}
    return pd.DataFrame(rows).T.sort_index()


def _ok(f, s):
    try:
        f(s); return True
    except (KeyError, IndexError):
        return False


def holm(p):
    p = np.asarray(p); order = np.argsort(p); m = len(p)
    adj = np.empty(m); run = 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (m - r) * p[i])); adj[i] = run
    return adj


def neardup(folders):
    rows = []
    for f in sorted(f for res in folders for f in glob.glob(os.path.join(res, "samples_seed*.npz"))):
        S = dict(np.load(f))
        if "nn_dist" not in S:
            continue
        keep = S["nn_dist"] > NEAR
        y = S["y"]
        for name in [k[5:] for k in S if k.startswith("pred_")]:
            p = S["pred_" + name]
            for sub, m in (("all", np.ones_like(keep)), ("no_near_twins", keep)):
                yy, pp = y[m], p[m]
                rows.append(dict(seed=os.path.basename(f)[12:-4], model=name, subset=sub, n=int(m.sum()),
                                 acc=float((pp == yy).mean()), tpr=float(pp[yy == 1].mean()), fpr=float(pp[yy == 0].mean())))
        for name, key in (("abl_main", "abl_main_cert_exact"), ("abl_lgbm_main", "abl_lgbm_main_cert_exact")):
            if key in S:
                for sub, m in (("all", np.ones_like(keep)), ("no_near_twins", keep)):
                    mm = m & (y == 1)
                    rows.append(dict(seed=os.path.basename(f)[12:-4], model=name + "_cert_r1", subset=sub, n=int(mm.sum()),
                                     tpr=float(S[key][mm, 1].mean())))
        rows.append(dict(seed=os.path.basename(f)[12:-4], model="near_twin_share", subset="malware",
                         n=int((y == 1).sum()), tpr=float((~keep[y == 1]).mean()), fpr=float((~keep[y == 0]).mean())))
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", nargs="+", required=True,
                    help="one or more results folders of the family-split run (seeds pooled; outputs go to the first)")
    ap.add_argument("--random", nargs="+", default=None)
    ap.add_argument("--paper", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paper"))
    a = ap.parse_args()
    out, N = [], {}
    for split, folders in (("family", a.family), ("random", a.random)):
        if not folders:
            continue
        res = folders[0]
        D = per_seed(folders)
        for k in D.columns:
            x = D[k].dropna()
            if len(x):
                m, s, lo, hi = tint(x)
                out.append(dict(split=split, metric=k, n_seeds=len(x), mean=m, std=s, ci_lo=lo, ci_hi=hi))
        if split == "family":
            comp = []
            for lab, A, B in COMPARISONS:
                d = (D[A] - D[B]).dropna()
                m, s, lo, hi = tint(d)
                p = st.ttest_rel(D[A].loc[d.index], D[B].loc[d.index]).pvalue if len(d) > 1 else np.nan
                comp.append(dict(comparison=lab, n_seeds=len(d), mean_diff=m, ci_lo=lo, ci_hi=hi, p=p))
            C = pd.DataFrame(comp)
            C["p_holm"] = holm(C.p.fillna(1.0).values)
            C.to_csv(os.path.join(res, "stats_comparisons.csv"), index=False)
            print(C.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
            for i, r in C.iterrows():
                k = "Cmp" + "ABCDEF"[i]
                N[k + "Diff"], N[k + "Lo"], N[k + "Hi"] = (f"{100 * r.mean_diff:.1f}", f"{100 * r.ci_lo:.1f}", f"{100 * r.ci_hi:.1f}")
                N[k + "P"] = f"{r.p_holm:.3f}" if r.p_holm >= 0.001 else "<0.001"
                N[k + "Int"] = f"\\ensuremath{{[{100 * r.ci_lo:.1f},\\,{100 * r.ci_hi:.1f}]}}"   # the one interval macro
            nd = neardup(folders)
            nd.to_csv(os.path.join(res, "stats_neardup.csv"), index=False)
            tw = nd[nd.model == "near_twin_share"]
            N["NearTwinFamMal"], N["NearTwinFamBen"] = f"{100 * tw.tpr.mean():.1f}", f"{100 * tw.fpr.mean():.1f}"
            q = nd[nd.model != "near_twin_share"].groupby(["model", "subset"])[["tpr", "acc"]].mean()
            shift = [abs(q.loc[(m, "all"), c] - q.loc[(m, "no_near_twins"), c]) for m in q.index.levels[0]
                     for c in ("tpr", "acc") if not np.isnan(q.loc[(m, "all"), c])]
            N["NearTwinMaxShift"] = f"{100 * max(shift):.1f}"
    S = pd.DataFrame(out)
    S.to_csv(os.path.join(a.family[0], "stats_summary.csv"), index=False)
    # per-model macros: <Fam|Rand><Name> mean, ...Lo / ...Hi 95% interval (percent, 1 decimal)
    for _, r in S.iterrows():
        k = ("Fam" if r.split == "family" else "Rand") + MACRO[r.metric]
        N[k], N[k + "Lo"], N[k + "Hi"] = (f"{100 * v:.1f}" for v in (r["mean"], r.ci_lo, r.ci_hi))
        N["NSeeds" + ("Fam" if r.split == "family" else "Rand")] = str(int(r.n_seeds))
    if "family" in set(S.split):
        C = pd.read_csv(os.path.join(a.family[0], "stats_comparisons.csv"))
        N["CmpFAbs"] = f"{abs(100 * C.mean_diff.iloc[5]):.1f}"
    if {"family", "random"} <= set(S.split):
        # random - family gap over certified-detection metrics (those at >= 1% on either split)
        P = S.pivot(index="metric", columns="split", values="mean")
        P = P[[m.startswith("cert") for m in P.index]]
        P = P[(P.family >= 0.01) | (P.random >= 0.01)]
        gap = 100 * (P.random - P.family)
        N["RandFamGapMin"], N["RandFamGapMax"] = f"{gap.min():.0f}", f"{gap.max():.0f}"
    with open(os.path.join(a.paper, "tables", "numbers_stats.tex"), "w") as f:
        f.write("% auto-generated by tools/stats.py -- do not edit by hand\n")
        for k, v in N.items():
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(f"summary rows {len(S)}; comparisons and near-duplicate tables written")


if __name__ == "__main__":
    main()
