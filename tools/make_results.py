"""Stage 4b: tables, figures and macros of the Results section (Section 6) from the final Stage 3 results.

    python tools/make_results.py [--paper paper]

Family split (main): results_family + results_family_s34 (5 seeds; smoothing on seeds 0-2). Random split: results_random.
Also reads results_fulldata, results_temporal_decay/decay.csv, results_eps_sweep, ps_results/eps_coverage.csv and
results_family/stats_comparisons.csv (run tools/stats.py, tools/temporal_decay.py and tools/eps_sweep.py --analyse first).
"+-" in the tables is the half-width of the 95% t-interval over seeds.
Writes paper/tables/tab_{main,attacks,group_cert,certified_training,comparisons,split_gap,temporal,smoothing}.tex,
paper/figures/fig_{decay,per_category,eps_coverage}.pdf and paper/tables/numbers_results.tex (macros Res...).
Supersedes make_figures.py for the paper (that script writes the draft-v1 tables).
"""
import argparse, json, os, sys
import numpy as np
import pandas as pd
from scipy import stats as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
FAM = ["results_family", "results_family_s34"]
EDIT9 = ["E1_overlay", "E2_strings", "E3_section", "E4_imports", "E5_timestamp", "E6_secnames", "E7_header",
         "E8_strip", "E10_hdrfields"]
FAMS = ["F_content", "F_section", "F_import", "F_strip"]
FAMLAB = {"F_content": "content", "F_section": "section", "F_import": "import", "F_strip": "strip"}


def seeds_of(folders):
    out = {}
    for f in folders:
        R = json.load(open(os.path.join(ROOT, f, "results.json")))
        for k, s in R["seeds"].items():
            out[int(k)] = s
    return dict(sorted(out.items())), R["config"]


def ci(x):
    x = np.asarray([v for v in x if v is not None and not np.isnan(v)], float)
    if len(x) < 2:
        return (x.mean() if len(x) else np.nan), 0.0
    return x.mean(), st.t.ppf(0.975, len(x) - 1) * x.std(ddof=1) / np.sqrt(len(x))


def pm(x, scale=100, d=1):
    m, h = ci(x)
    return "--" if np.isnan(m) else f"{scale * m:.{d}f}\\,$\\pm$\\,{scale * h:.{d}f}"


def mean(x, scale=100, d=1):
    x = [v for v in x if v is not None]
    return "--" if not x else f"{scale * np.mean(x):.{d}f}"


def tabular(cols, head, rows, notes=()):
    T = ["\\begin{tabular}{" + cols + "}", "\\toprule"] + head + ["\\midrule"]
    T += [" & ".join(r) + " \\\\" if isinstance(r, (list, tuple)) else r for r in rows]
    return "\n".join(T + ["\\bottomrule", "\\end{tabular}"] + [f"% {n}" for n in notes])


def wilson(k, n, z=1.96):
    if n == 0:
        return np.nan, np.nan
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    a = ap.parse_args()
    tdir, fdir = os.path.join(a.paper, "tables"), os.path.join(a.paper, "figures")
    S, cfg = seeds_of(FAM)
    Sr, _ = seeds_of(["results_random"])
    seeds = list(S.values())
    hid = lambda h: "2381--" + "--".join(str(v) for v in h) + "--2"
    N = {"ResNSeedsSmooth": str(sum("smoothing" in s for s in seeds)),
         "ResNCategories": str(seeds[0]["data"]["n_categories"]), "ResNFamilies": str(seeds[0]["data"]["n_families"])}
    ct = lambda s, m: s["certified_training"][m]
    ab = lambda s, m: s["ablation"][m]
    i05 = cfg["cert_eps_list"].index(cfg["ibp_train_eps"])

    # ---------------- models: clean metrics and group-attack key ----------------
    MODELS = [
        ("LightGBM (all features)", lambda s: s["lightgbm"], "lightgbm"),
        ("LightGBM, monotonic", lambda s: s["lightgbm_mono"], "lightgbm_mono"),
        (f"MLP {hid(cfg['hidden'])}", lambda s: s["mlp"], "mlp"),
        (f"MLP {hid(cfg['ibp_hidden'])}", lambda s: ct(s, "standard")["clean"], "ct_standard"),
        ("PGD-AT on $B_\\epsilon$", lambda s: s["pgd_at"], "pgd_at"),
        ("Group ablation, MLP views, main", lambda s: ab(s, "main")["clean"], "ablation_main"),
        ("Group ablation, MLP views, second", lambda s: ab(s, "second")["clean"], "ablation_second"),
        ("Group ablation, MLP views, EMBER groups", lambda s: ab(s, "ember")["clean"], "ablation_ember"),
        ("Group ablation, LightGBM views, main", lambda s: ab(s, "lgbm_main")["clean"], "ablation_lgbm_main"),
        ("Group ablation, LightGBM views, second", lambda s: ab(s, "lgbm_second")["clean"], "ablation_lgbm_second"),
        ("CROWN-IBP, uniform ball", lambda s: ct(s, "crownibp_unc")["clean"], "ct_crownibp_unc"),
        ("CROWN-IBP, constrained box", lambda s: ct(s, "crownibp")["clean"], "ct_crownibp"),
        ("CROWN-IBP, edit-aware", lambda s: ct(s, "crownibp_edit")["clean"], "ct_crownibp_edit"),
        ("Giri et al., re-implementation", None, "giri_reimpl"),
    ]
    ga_of = lambda k, r=1: [s["group_attack"][k][r] for s in seeds if k in s["group_attack"]]   # Giri: smoothing seeds only
    rows = []
    for lab, get, ga in MODELS:
        if get is None:
            sm = [s for s in seeds if "smoothing" in s]
            rows.append([lab, pm([s["smoothing"]["giri_reimpl"]["clean_acc"] for s in sm]), "--", "--"])
            continue
        rows.append([lab] + [pm([get(s)[m] for s in seeds]) for m in ("acc", "tpr", "fpr")])
    open(os.path.join(tdir, "tab_main.tex"), "w").write(tabular(
        "lrrr", ["Detector & Accuracy & TPR & FPR \\\\"], rows,
        [f"family split, {len(seeds)} seeds; +- = half-width of the 95% t-interval; Giri accuracy on "
         f"{N['ResNSeedsSmooth']} seeds (abstentions count as errors)"]))

    # ---------------- group-transplant attack, r = 0..3 ----------------
    rmax = cfg["group_attack_max_r"]
    rows = [[lab] + [mean(ga_of(ga, r)) for r in range(rmax + 1)] for lab, _, ga in MODELS]
    open(os.path.join(tdir, "tab_attacks.tex"), "w").write(tabular(
        "l" + "r" * (rmax + 1), ["Detector & " + " & ".join(f"$r={r}$" for r in range(rmax + 1)) + " \\\\"], rows,
        [f"malware detected (%) under the group-transplant attack in the main partition's groups; mean over "
         f"{len(seeds)} seeds; {cfg['group_attack_points']} malware, {cfg['group_attack_donors']} donors"]))
    gam = ga_of
    N["ResGaMlp"] = mean(gam("mlp")); N["ResGaMlpEvade"] = f"{100 - 100 * np.mean(gam('mlp')):.1f}"
    N["ResGaPgdAt"] = mean(gam("pgd_at")); N["ResGaMono"] = mean(gam("lightgbm_mono"))
    N["ResGaAblMain"] = mean(gam("ablation_main")); N["ResGaGiri"] = mean(gam("giri_reimpl"))
    N["ResGaEdit"] = mean(gam("ct_crownibp_edit"))
    N["ResGaLgbmViewsRTwo"] = mean(gam("ablation_lgbm_main", 2))
    N["ResGaLgbmSecondRThree"] = mean(gam("ablation_lgbm_second", 3))
    N["ResGaMaxOther"] = f"{100 * max(np.mean(gam(k)) for k in ('lightgbm', 'lightgbm_mono', 'mlp', 'pgd_at', 'giri_reimpl', 'ct_standard', 'ct_pgd_at', 'ct_crownibp', 'ct_crownibp_unc', 'ct_crownibp_edit')):.1f}"

    # ---------------- group certificates per edit type ----------------
    CFGS = [("main", "MLP"), ("lgbm_main", "LightGBM"), ("second", "MLP"), ("lgbm_second", "LightGBM"), ("ember", "MLP")]
    lab_e = {"E1_overlay": "E1 overlay append", "E2_strings": "E2 string padding", "E3_section": "E3 section injection",
             "E4_imports": "E4 import addition", "E5_timestamp": "E5 timestamp", "E6_secnames": "E6 section renaming",
             "E7_header": "E7 checksum, DOS header", "E8_strip": "E8 signature/debug strip",
             "E10_hdrfields": "E10 header versions"}
    rows = []
    for e in EDIT9:
        r_main, r_sec, r_emb = (seeds[0]["ablation"][c]["cert_by_edit"][e]["r_needed"] for c in ("main", "second", "ember"))
        rows.append([lab_e[e], str(r_main), str(r_sec), str(r_emb)] +
                    [mean([ab(s, c)["cert_by_edit"][e]["cert_tpr"] for s in seeds]) for c, _ in CFGS])
    rows.append("\\midrule")
    rows.append(["Mean over the nine types", "", "", ""] +
                [pm([np.mean([ab(s, c)["cert_by_edit"][e]["cert_tpr"] for e in EDIT9]) for s in seeds]) for c, _ in CFGS])
    rows.append(["Clean accuracy", "", "", ""] + [pm([ab(s, c)["clean"]["acc"] for s in seeds]) for c, _ in CFGS])
    rows.append(["Views; largest certifiable $r$", "", "", ""] +
                [f"{seeds[0]['ablation'][c]['n_subsets']}; {seeds[0]['ablation'][c]['ceiling_r']}" for c, _ in CFGS])
    open(os.path.join(tdir, "tab_group_cert.tex"), "w").write(tabular(
        "lrrrrrrrr",
        [" & \\multicolumn{3}{c}{$r$ needed} & \\multicolumn{5}{c}{Certified detection (\\%)} \\\\",
         "\\cmidrule(lr){2-4}\\cmidrule(lr){5-9}",
         "Edit type & main & second & EMBER & main, MLP & main, LightGBM & second, MLP & second, LightGBM & EMBER, MLP \\\\"],
        rows, [f"family split, {len(seeds)} seeds; main = aligned5 k=2, second = aligned7 k=1, EMBER = 9 groups k=1"]))
    for c, stem in (("lgbm_second", "LgbmSecond"), ("second", "MlpSecond")):
        for r in (1, 2, 3):
            N[f"ResCert{stem}R{['', 'One', 'Two', 'Three'][r]}"] = mean([ab(s, c)["cert_tpr_exact"][r] for s in seeds])
    N["ResAccLgbmSecond"] = mean([ab(s, "lgbm_second")["clean"]["acc"] for s in seeds])
    N["ResFprLgbmSecond"] = mean([ab(s, "lgbm_second")["clean"]["fpr"] for s in seeds])
    N["ResFprAblSecond"] = mean([ab(s, "second")["clean"]["fpr"] for s in seeds])
    gain = max(np.mean([ab(s, c)["cert_tpr_exact"][r] - ab(s, c)["cert_tpr"][r] for s in seeds])
               for c in ("main", "second", "ember", "lgbm_main", "lgbm_second") for r in range(len(seeds[0]["ablation"][c]["cert_tpr"])))
    N["ResExactGainMax"] = f"{100 * gain:.2f}"
    N["ResEmberROne"] = mean([ab(s, "ember")["cert_tpr_exact"][1] for s in seeds])
    nv = sum(ab(s, c)["violations"] for s in seeds for c in s["ablation"]) + \
        sum(v["violations"] for s in seeds for v in s["certified_training"].values())
    N["ResNViolations"] = str(nv)
    N["ResCorpusViolations"] = str(sum(v["corpus_violations"] for s in seeds for v in s["certified_training"].values()))
    N["ResCorpusChecked"] = f"{seeds[0]['certified_training']['crownibp_edit']['corpus_checked']:,}".replace(",", "{,}")

    # ---------------- certified training ----------------
    sw = json.load(open(os.path.join(ROOT, "results_eps_sweep", "results.json")))["seeds"]
    i1 = cfg["family_scales"].index(1.0)
    CT = [("Standard MLP", "standard"), ("PGD-AT", "pgd_at"),
          (f"Uniform ball, $\\epsilon={cfg['unc_train_eps']:g}$ (tuned)", "crownibp_unc"),
          (f"Constrained box, $\\epsilon={cfg['box_train_eps']:g}$", "crownibp"), ("Edit-aware", "crownibp_edit")]
    rows = []
    for lab, m in CT:
        rows.append([lab, mean([ct(s, m)["clean"]["acc"] for s in seeds]), mean([ct(s, m)["clean"]["fpr"] for s in seeds])] +
                    [mean([ct(s, m)["family_cert"][f][i1] for s in seeds]) for f in FAMS] +
                    [pm([ct(s, m)["family_cert"]["mean_over_families_t1"] for s in seeds]),
                     mean([ct(s, m)["cert_tpr"][i05] for s in seeds])])
    one = [sw[k]["models"]["1"] for k in sorted(sw)]
    rows.append(["Uniform ball, $\\epsilon=1$ (sweep)", mean([c["clean"]["acc"] for c in one]),
                 mean([c["clean"]["fpr"] for c in one])] +
                [mean([c["family_cert"][f][i1] for c in one]) for f in FAMS] +
                [pm([c["family_cert"]["mean_over_families_t1"] for c in one]), "--"])
    open(os.path.join(tdir, "tab_certified_training.tex"), "w").write(tabular(
        "lrrrrrrrr",
        [" & & & \\multicolumn{5}{c}{Certified over $T_f(1)$ (\\%)} & \\\\", "\\cmidrule(lr){4-8}",
         f"CROWN-IBP training & Acc. & FPR & content & section & import & strip & mean & $B_\\epsilon$, $\\epsilon={cfg['ibp_train_eps']:g}$ \\\\"],
        rows, [f"family split, {len(seeds)} seeds (sweep row: results_eps_sweep); networks {hid(cfg['ibp_hidden'])}"]))
    for m, stem in (("crownibp", "Box"), ("crownibp_unc", "Unif")):
        N[f"Res{stem}OnBox"] = mean([ct(s, m)["cert_tpr"][i05] for s in seeds])
        N[f"Res{stem}OnBall"] = mean([ct(s, m)["cert_tpr_unconstrained"][i05] for s in seeds])
    N["ResEditOnBox"] = mean([ct(s, "crownibp_edit")["cert_tpr"][i05] for s in seeds])
    N["ResStdOnBox"] = mean([ct(s, "standard")["cert_tpr"][i05] for s in seeds])
    N["ResEditAllFam"] = mean([ct(s, "crownibp_edit")["family_cert"]["all_families"][i1] for s in seeds])
    N["ResEditTTwo"] = mean([np.mean([ct(s, "crownibp_edit")["family_cert"][f][cfg["family_scales"].index(2.0)] for f in FAMS]) for s in seeds])
    N["ResTrainEps"] = f"{cfg['ibp_train_eps']:g}"

    # L-inf coverage of real edits vs certified detection on B_eps (replaces the quick-pilot version of fig_eps_coverage)
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cov = pd.read_csv(os.path.join(ROOT, "ps_results", "eps_coverage.csv")).set_index("eps")
    eps = cfg["cert_eps_list"]
    fig, ax = plt.subplots(figsize=(5.5, 3.2))
    ax.plot(eps, [100 * cov.loc[e, "all_in_scope"] for e in eps], "k-", lw=2, label="measured edits inside $B_\\epsilon$")
    for lab, m in CT:
        ax.plot(eps, [100 * np.mean([ct(s, m)["cert_tpr"][i] for s in seeds]) for i in range(len(eps))], "o-", ms=3,
                label=lab.replace(" (tuned)", ""))
    ax.set_xscale("log"); ax.set_xlabel("$\\epsilon$ (standardised units)"); ax.set_ylabel("%"); ax.set_ylim(0, 100)
    ax.legend(fontsize=6.5); fig.tight_layout(); fig.savefig(os.path.join(fdir, "fig_eps_coverage.pdf")); plt.close(fig)

    # ---------------- comparisons ----------------
    C = pd.read_csv(os.path.join(ROOT, "results_family", "stats_comparisons.csv"))
    labs = ["Edit-aware vs uniform-ball CROWN-IBP, certified over $T_f(1)$",
            f"Box vs uniform-ball CROWN-IBP, certified at $\\epsilon={cfg['ibp_train_eps']:g}$",
            "Aligned (main) vs EMBER groups, certified over the nine edit types",
            "LightGBM views vs MLP views (main), certified at $r=1$",
            "LightGBM views (main) vs LightGBM, detected under group attack at $r=1$",
            "LightGBM views (main) vs LightGBM, clean accuracy"]
    pf = lambda p: "$<0.001$" if p < 0.001 else f"{p:.3f}"
    rows = [[str(i + 1), labs[i], f"${100 * r.mean_diff:+.1f}$", f"$[{100 * r.ci_lo:.1f},\\,{100 * r.ci_hi:.1f}]$",
             pf(r.p), pf(r.p_holm)] for i, r in C.iterrows()]
    open(os.path.join(tdir, "tab_comparisons.tex"), "w").write(tabular(
        "rlrrrr", ["\\# & Comparison (A vs B) & A $-$ B (points) & 95\\% interval & $p$ & Holm $p$ \\\\"], rows,
        [f"paired over {int(C.n_seeds.iloc[0])} family-split seeds; declared before any test evaluation (log 3-1)"]))

    # ---------------- random vs family ----------------
    Ssum = pd.read_csv(os.path.join(ROOT, "results_family", "stats_summary.csv"))
    P = {sp: Ssum[Ssum.split == sp].set_index("metric") for sp in ("family", "random")}
    GAP = [("acc_lightgbm", "LightGBM, accuracy"), ("acc_abl_lgbm_main", "LightGBM views (main), accuracy"),
           ("cert_r1_abl_lgbm_main", "LightGBM views (main), certified at $r=1$"),
           ("cert_r1_abl_main", "MLP views (main), certified at $r=1$"),
           ("cert_edits_abl_lgbm_main", "LightGBM views (main), certified over 9 edit types"),
           ("cert_edits_abl_second", "MLP views (second), certified over 9 edit types"),
           ("cert_edits_abl_ember", "MLP views (EMBER), certified over 9 edit types"),
           ("gattack_r1_abl_lgbm_main", "LightGBM views (main), detected under group attack"),
           ("certT1_crown_edit", "Edit-aware CROWN-IBP, certified over $T_f(1)$"),
           ("cert005_crown_unc", f"Uniform-ball CROWN-IBP, certified at $\\epsilon={cfg['ibp_train_eps']:g}$")]
    f3 = lambda r: f"{100 * r['mean']:.1f} [{100 * r.ci_lo:.1f}, {100 * r.ci_hi:.1f}]"
    rows = [[lab, f3(P["random"].loc[m]), f3(P["family"].loc[m]),
             f"{100 * (P['random'].loc[m, 'mean'] - P['family'].loc[m, 'mean']):.1f}"] for m, lab in GAP]
    nr, nf = int(P["random"].n_seeds.iloc[0]), int(P["family"].n_seeds.iloc[0])
    open(os.path.join(tdir, "tab_split_gap.tex"), "w").write(tabular(
        "lrrr", [f"Metric (\\%) & Random split ({nr} seeds) & Family split ({nf} seeds) & Gap (points) \\\\"], rows,
        ["mean [95% t-interval]"]))

    # ---------------- full-data check ----------------
    F = json.load(open(os.path.join(ROOT, "results_fulldata", "results.json")))["seeds"]["0"]
    s0 = S[0]
    N["ResFullN"] = f"{F['data']['n_train'] + F['data']['n_val'] + F['data']['n_test']:,}".replace(",", "{,}")
    N["ResFullAccLgbm"], N["ResSubAccLgbm"] = mean([F["lightgbm"]["acc"]]), mean([s0["lightgbm"]["acc"]])
    N["ResFullAccAblMain"], N["ResSubAccAblMain"] = mean([F["ablation"]["main"]["clean"]["acc"]]), mean([s0["ablation"]["main"]["clean"]["acc"]])
    N["ResFullCertAblMain"] = mean([F["ablation"]["main"]["cert_tpr_exact"][1]])
    N["ResSubCertAblMain"] = mean([s0["ablation"]["main"]["cert_tpr_exact"][1]])
    N["ResFullViolations"] = str(F["ablation"]["main"]["violations"])

    # ---------------- smoothing ----------------
    sm = {k: s for k, s in S.items() if "smoothing" in s}
    RADII = (0.0, 0.25, 0.5, 0.75)
    rows = []
    for key, lab in (("isotropic_0.25", "Isotropic, $\\sigma=0.25$"), ("isotropic_0.5", "Isotropic, $\\sigma=0.5$"),
                     ("giri_reimpl", f"Giri et al.\\ re-impl., $\\sigma={cfg['giri_sigma']:g}$")):
        cert = {r: [] for r in RADII}
        for k in sm:
            Z = np.load(os.path.join(ROOT, "results_family", f"samples_seed{k}.npz"))
            y, p, rad = Z["rs_y"], Z[f"rs_{key}_pred"], Z[f"rs_{key}_rad"]
            for r in RADII:
                cert[r].append(float(((p == 1) & (rad >= r))[y == 1].mean()))
        rows.append([lab, mean([s["smoothing"][key]["clean_acc"] for s in sm.values()]),
                     mean([s["smoothing"][key]["abstain"] for s in sm.values()])] + [mean(cert[r]) for r in RADII])
        st_ = key.replace("isotropic_0.25", "Quarter").replace("isotropic_0.5", "Half").replace("giri_reimpl", "Giri")
        N[f"ResRs{st_}Acc"] = rows[-1][1]; N[f"ResRs{st_}CertHalf"] = mean(cert[0.5])
    open(os.path.join(tdir, "tab_smoothing.tex"), "w").write(tabular(
        "lrrrrrr", [" & & & \\multicolumn{4}{c}{Certified detection (\\%) at $\\ell_2$ radius} \\\\", "\\cmidrule(lr){4-7}",
                    "Smoothing & Acc. & Abstain & " + " & ".join(f"{r:g}" for r in RADII) + " \\\\"], rows,
        [f"family split, seeds {sorted(sm)}; n = {cfg['n_cert']} noise samples per point, alpha = {cfg['alpha']}"]))
    N["ResRsN"] = f"{cfg['n_cert']:,}".replace(",", "{,}")

    # ---------------- temporal ----------------
    D = pd.read_csv(os.path.join(ROOT, "results_temporal_decay", "decay.csv"))
    M = D.groupby(["cutoff", "bin"]).mean(numeric_only=True).reset_index()
    rows = []
    for _, r in M.iterrows():
        rows.append([r.cutoff, r.bin, f"{r.n_malware:,.0f}", f"{r.n_benign:,.0f}", mean([r.tpr_lightgbm]), mean([r.fpr_lightgbm]),
                     mean([r.cert_r1_abl_lgbm_main]), mean([r.cert_r1_abl_main]), mean([r.cert_t1_crown_edit])])
    open(os.path.join(tdir, "tab_temporal.tex"), "w").write(tabular(
        "llrrrrrrr", [" & & & & \\multicolumn{2}{c}{LightGBM} & \\multicolumn{3}{c}{Certified detection} \\\\",
                      "\\cmidrule(lr){5-6}\\cmidrule(lr){7-9}",
                      "Cut-off & Test month & Malware & Benign & TPR & FPR & LGBM views, $r=1$ & MLP views, $r=1$ & edit-aware, $T_f(1)$ \\\\"],
        rows, ["mean over 3 seeds per cut-off; months with fewer than 200 malware or benign would be merged (none were)"]))
    fig, ax = plt.subplots(figsize=(6, 3.3))
    for k, lab, c in (("cert_r1_abl_lgbm_main", "LightGBM views, $r=1$", "C0"), ("cert_r1_abl_main", "MLP views, $r=1$", "C1"),
                      ("cert_t1_crown_edit", "edit-aware CROWN-IBP, $T_f(1)$", "C2"), ("tpr_lightgbm", "LightGBM TPR (clean)", "0.5")):
        for cut, ls in zip(sorted(M.cutoff.unique()), ("-", "--")):
            g = M[M.cutoff == cut]
            ax.plot(g.bin, 100 * g[k], ls, color=c, marker="o", ms=3, label=f"{lab}, train to {cut}")
    ax.set_ylabel("% of test malware"); ax.set_ylim(0, 100); ax.tick_params(axis="x", rotation=45, labelsize=7)
    ax.legend(fontsize=5.5, ncol=2, loc="lower left"); fig.tight_layout()
    fig.savefig(os.path.join(fdir, "fig_decay.pdf")); plt.close(fig)
    low = M.loc[M.cert_r1_abl_lgbm_main.idxmin()]
    N["ResTdLowMonth"], N["ResTdLowLgbmViews"] = low.bin, mean([low.cert_r1_abl_lgbm_main])

    # ---------------- per category (Am3, B6): pooled over seeds, Wilson intervals ----------------
    from malcert.config import get_config
    from malcert.data import load_subset, split_indices
    dcfg = get_config("full", split="family", data_npz=os.path.join(ROOT, "data", "bodmas.npz"),
                      meta_csv=os.path.join(ROOT, "data", "bodmas_metadata.csv"),
                      cat_csv=os.path.join(ROOT, "data", "bodmas_malware_category.csv"))
    data = load_subset(dcfg, seed=0)
    distinct, pooled = {}, []
    for k in S:
        te = split_indices(data, dcfg, seed=k)["te"]
        Z = np.load(os.path.join(ROOT, [f for f in FAM if os.path.exists(os.path.join(ROOT, f, f"samples_seed{k}.npz"))][0],
                                 f"samples_seed{k}.npz"))
        assert (data["y"][te] == Z["y"]).all(), "split does not reproduce the saved test part"
        mal = Z["y"] == 1
        for i, c in zip(te[mal], Z["category"][mal]):
            distinct.setdefault(c, set()).add(int(i))
        pooled.append(pd.DataFrame(dict(cat=Z["category"][mal], det=Z["pred_lightgbm"][mal],
                                        det_v=Z["pred_abl_lgbm_main"][mal], cert_v=Z["abl_lgbm_main_cert_exact"][mal, 1])))
    Pc = pd.concat(pooled)
    small = {c for c, v in distinct.items() if len(v) < 30}
    Pc["cat"] = Pc.cat.where(~Pc.cat.isin(small), "other")
    nd = {c: len(v) for c, v in distinct.items() if c not in small}
    nd["other"] = sum(len(v) for c, v in distinct.items() if c in small)
    cats = Pc.groupby("cat").size().sort_values(ascending=False).index.tolist()
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    for j, (col, lab) in enumerate((("det", "LightGBM, detected"), ("det_v", "LightGBM views, detected"),
                                    ("cert_v", "LightGBM views, certified $r=1$"))):
        k_ = [Pc[Pc.cat == c][col].sum() for c in cats]; n_ = [(Pc.cat == c).sum() for c in cats]
        p_ = [100 * k / n for k, n in zip(k_, n_)]; w = [wilson(k, n) for k, n in zip(k_, n_)]
        x = np.arange(len(cats)) + (j - 1) * 0.27
        ax.bar(x, p_, 0.27, label=lab, yerr=[[p - 100 * lo for p, (lo, hi) in zip(p_, w)],
                                              [100 * hi - p for p, (lo, hi) in zip(p_, w)]], capsize=1.5)
    ax.set_xticks(np.arange(len(cats))); ax.set_xticklabels([f"{c}\n($n$={nd[c]})" for c in cats], fontsize=6.5)
    ax.set_ylabel("% of test malware"); ax.set_ylim(0, 100)
    ax.legend(fontsize=6.5, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False)   # outside the bars
    fig.tight_layout(); fig.savefig(os.path.join(fdir, "fig_per_category.pdf")); plt.close(fig)
    N["ResCatSmall"] = ", ".join(sorted(small)) if small else "none"
    # the two named categories (not "other") with the lowest certified detection at r = 1
    cert_c = {c: Pc[Pc.cat == c].cert_v.mean() for c in cats if c != "other"}
    for tag, c in zip(("A", "B"), sorted(cert_c, key=cert_c.get)[:2]):
        n_c = (Pc.cat == c).sum(); k_c = Pc[Pc.cat == c].cert_v.sum(); lo, hi = wilson(k_c, n_c)
        N[f"ResCatWeak{tag}"], N[f"ResCatWeak{tag}N"] = c.replace("informationstealer", "information stealer"), str(nd[c])
        N[f"ResCatWeak{tag}Cert"] = f"{100 * cert_c[c]:.1f}"
        N[f"ResCatWeak{tag}Lo"], N[f"ResCatWeak{tag}Hi"] = f"{100 * lo:.1f}", f"{100 * hi:.1f}"
    N["ResCatAllCert"] = f"{100 * Pc.cert_v.mean():.1f}"

    with open(os.path.join(tdir, "numbers_results.tex"), "w") as f:
        f.write("% auto-generated by tools/make_results.py -- do not edit by hand\n")
        for k, v in N.items():
            assert k.isalpha(), k
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(f"{len(N)} macros; tables and figures written")
    for k, v in N.items():
        print(f"  {k} = {v}")


if __name__ == "__main__":
    main()
