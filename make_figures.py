"""Turn results/results.json (+ samples_seed*.npz) into paper figures, LaTeX tables and
a numbers.tex file of \\newcommand macros that the manuscript uses, so every number in
the paper comes straight from the experiment output.

    python make_figures.py --res results --paper ../paper
"""
import argparse, glob, json, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# validated categorical palette (light mode), fixed order
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
GRAY = "#8a8985"
plt.rcParams.update({"font.family": "serif", "font.size": 8.5, "axes.titlesize": 9,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.6,
                     "lines.linewidth": 1.6, "lines.markersize": 4, "legend.frameon": False,
                     "savefig.dpi": 300, "savefig.bbox": "tight"})


def ms(vals):
    a = np.array(vals, dtype=float)
    return a.mean(0), (a.std(0) if len(a) > 1 else np.zeros_like(a.mean(0)))


def fmt(m, s, pct=True, nd=1):
    k = 100 if pct else 1
    return f"{m * k:.{nd}f}" + (f"$\\pm${s * k:.{nd}f}" if s > 0 else "")


def save(fig, out, name):
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"))
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--res", default="results")
    ap.add_argument("--paper", default=None, help="copy figures/tables/numbers here")
    a = ap.parse_args()
    R = json.load(open(os.path.join(a.res, "results.json")))
    cfg, seeds = R["config"], list(R["seeds"].values())
    S = [dict(np.load(f)) for f in sorted(glob.glob(os.path.join(a.res, "samples_seed*.npz")))]
    fdir, tdir = os.path.join(a.res, "figures"), os.path.join(a.res, "tables")
    os.makedirs(fdir, exist_ok=True); os.makedirs(tdir, exist_ok=True)
    N = {}                                    # macros for numbers.tex
    eps, ceps, sig = cfg["eps_list"], cfg["cert_eps_list"], cfg["sigmas"]
    D = seeds[0]["data"]

    # ---------------- Fig 1: dataset composition ----------------
    cats = {k: v for k, v in D["categories"].items() if k != "benign"}
    order = sorted(cats, key=cats.get)
    fig, ax = plt.subplots(figsize=(3.4, 2.9))
    ax.barh(range(len(order)), [cats[c] for c in order], color=C[0], height=0.65)
    for i, c in enumerate(order):
        ax.text(cats[c] * 1.08, i, f"{cats[c]:,}", va="center", fontsize=7, color="#52514e")
    ax.set_yticks(range(len(order)), order); ax.set_xscale("log"); ax.set_xlim(1, 3e4)
    ax.set_xlabel("Samples in 30K subset (log scale)"); ax.grid(axis="y", visible=False)
    ax.set_title(f"Malware categories ({D['n_malware']:,} malware, {D['n_benign']:,} benign)")
    save(fig, fdir, "fig_dataset")

    # ---------------- Fig 2: C1 attacks ----------------
    fig, axs = plt.subplots(1, 2, figsize=(7, 2.6), sharey=True)
    for ax, atk in zip(axs, ("fgsm", "pgd")):
        for ci, (mname, lab) in enumerate((("mlp", "Standard MLP"), ("pgd_at", "PGD-AT"))):
            for tm, ls in (("unconstrained", "--"), ("constrained", "-")):
                m, s = ms([sd["attacks"][mname][tm][atk] for sd in seeds])
                ax.plot(eps, m * 100, ls, color=C[ci], marker="o", label=f"{lab}, {tm}")
                ax.fill_between(eps, (m - s) * 100, (m + s) * 100, color=C[ci], alpha=0.12, lw=0)
        ax.set_xscale("log"); ax.set_xlabel(r"$\ell_\infty$ budget $\epsilon$ (standardised units)")
        ax.set_title(atk.upper())
    axs[0].set_ylabel("Malware still detected (%)"); axs[0].set_ylim(-3, 103)
    h, l = axs[0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=4, fontsize=7, bbox_to_anchor=(0.5, -0.02))
    save(fig, fdir, "fig_attacks")

    # ---------------- Fig 3: C2a group certificates ----------------
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    rmax = cfg["group_attack_max_r"]
    for ci, k in enumerate(cfg["keep_list"]):
        m, s = ms([sd["ablation"][str(k)]["cert_tpr"] for sd in seeds])
        m = m[:rmax + 2]; rr = np.arange(len(m))
        ax.plot(rr, m * 100, "-", color=C[ci], marker="o", label=f"Certified, $k$={k}")
        me, _ = ms([sd["ablation"][str(k)]["empirical_tpr"] for sd in seeds])
        ax.plot(np.arange(len(me)), me * 100, ":", color=C[ci], marker="s", mfc="none",
                label=f"Empirical attack, $k$={k}")
    me, _ = ms([sd["group_attack_mlp"] for sd in seeds])
    ax.plot(np.arange(len(me)), me * 100, "--", color=GRAY, marker="x", label="Standard MLP, attack")
    ax.set_xlabel("Mutable feature groups modified, $r$"); ax.set_ylabel("Malware detected (%)")
    # every lower-right spot inside the axes is crossed by a curve (k=1 diagonal, zero lines), so the
    # legend sits at the lower right just outside the axes; the figure is widened to keep the plot size
    fig.set_size_inches(5.0, 2.7)
    ax.set_xticks(range(rmax + 2))                       # r counts whole groups: integer ticks only
    ax.set_ylim(-3, 103); ax.legend(fontsize=6.5, loc="lower left", bbox_to_anchor=(1.02, 0.0), ncol=1)
    save(fig, fdir, "fig_group_cert")

    # ---------------- Fig 4: C2b smoothing ----------------
    radii = np.linspace(0, 3.0 * max(sig), 121)
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    curves = {}
    for ci, sg in enumerate(sig):
        for var, ls in (("isotropic", "--"), ("subspace", "-")):
            key = f"{var}_{sg}"
            vals = []
            for sm in S:
                y, pr, rd = sm["rs_y"], sm[f"rs_{key}_pred"], sm[f"rs_{key}_rad"]
                mal = y == 1
                vals.append([((pr[mal] == 1) & (rd[mal] >= r)).mean() for r in radii])
            m, _ = ms(vals); curves[key] = m
            ax.plot(radii, m * 100, ls, color=C[ci], label=f"$\\sigma$={sg}, {var}")
    ax.set_xlabel(r"Certified $\ell_2$ radius (standardised units)"); ax.set_ylabel("Certified malware detection (%)")
    # lower right, lifted off the zero lines that run along the bottom after each curve's drop
    ax.set_ylim(-3, 103); ax.legend(fontsize=6.5, loc="lower right", bbox_to_anchor=(1.0, 0.1))
    save(fig, fdir, "fig_smoothing")

    # ---------------- Fig 5: C3 certified training ----------------
    V = [("standard", "Standard"), ("pgd_at", "PGD-AT"), ("ibp", "IBP"), ("crownibp", "CROWN-IBP"),
         ("crownibp_asym", "CROWN-IBP (asym.)")]
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    for ci, (v, lab) in enumerate(V):
        m, s = ms([sd["certified_training"][v]["cert_tpr"] for sd in seeds])
        ax.plot(ceps, m * 100, "-", color=C[ci], marker="o", label=lab)
    m, _ = ms([sd["certified_training"]["crownibp_asym"]["cert_tpr_unconstrained"] for sd in seeds])
    ax.plot(ceps, m * 100, ":", color=C[4], marker="s", mfc="none", label="CROWN-IBP (asym.), unconstr. box")
    ax.set_xscale("log"); ax.set_xlabel(r"$\ell_\infty$ budget $\epsilon$"); ax.set_ylabel("Certified malware detection (%)")
    ax.set_ylim(-3, 103); ax.legend(fontsize=6.5, loc="lower left")
    save(fig, fdir, "fig_certified_training")

    # ---------------- Fig 6: per-category certified detection ----------------
    te = cfg["ibp_train_eps"]
    cols = [("abl1_cert", 1, "Ablation $k$=1, $r$=1"), ("abl2_cert", 1, "Ablation $k$=2, $r$=1"),
            ("ct_crownibp_cert", None, f"CROWN-IBP, $\\epsilon$={te}"),
            ("ct_ibp_cert", None, f"IBP, $\\epsilon$={te}")]
    # Each seed has its own test split: compute the per-category rate within each seed, then average
    # the rates over the seeds in which the category appears. n = DISTINCT test files over all seeds
    # (union of the seeds' test indices; the splits overlap, so pooled appearances would overcount).
    # The test indices are recomputed from the seeded subset/split code, then checked against the
    # categories stored in samples_seed*.npz, so a mismatch fails loudly instead of mislabelling.
    from malcert.config import Config
    from malcert.data import select_subset, split_indices
    cfgo = Config(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in cfg.items()})
    sel, yall, meta = select_subset(cfgo, 0)                     # run_all uses seed 0 for the subset
    sub = dict(y=yall[sel], category=meta["category"].values[sel])
    te_union = set()
    for s, sm in zip(cfg["seeds"], S):
        te_idx = split_indices(sub, cfgo, seed=s)["te"]
        assert np.array_equal(sub["category"][te_idx], sm["category"]), f"split mismatch for seed {s}"
        te_union.update(te_idx.tolist())
    te_union = np.array(sorted(te_union))
    allcats = sorted(c for c in D["categories"] if c != "benign")
    npool = {c: int(sum((sm["category"] == c).sum() for sm in S)) for c in allcats}
    ndist = {c: int((sub["category"][te_union] == c).sum()) for c in allcats}
    clist = [c for c in allcats if npool[c] >= 3 * len(S)]      # >= 3 test samples per seed on average
    hidden = [c for c in allcats if c not in clist]
    M = np.full((len(clist), len(cols)), np.nan)
    for j, (key, r, _) in enumerate(cols):
        for i, c in enumerate(clist):
            rates = []
            for sm in S:
                sel = sm["category"] == c
                if key in sm and sel.any():
                    cert = sm[key][:, r] if r is not None else sm[key]
                    rates.append(cert[sel].mean())
            if rates:
                M[i, j] = np.mean(rates) * 100
    fig, ax = plt.subplots(figsize=(4.2, 0.28 * len(clist) + 1.0))
    im = ax.imshow(M, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            if not np.isnan(M[i, j]):
                ax.text(j, i, f"{M[i, j]:.0f}", ha="center", va="center", fontsize=6.5,
                        color="white" if M[i, j] > 60 else "#0b0b0b")
    ax.set_yticks(range(len(clist)), [f"{c} (n={ndist[c]})" for c in clist])
    ax.set_xticks(range(len(cols)), [c[2] for c in cols], rotation=25, ha="right")
    ax.grid(False); fig.colorbar(im, ax=ax, label="Certified detection (%)", shrink=0.8)
    save(fig, fdir, "fig_per_category")
    hl = [h.replace("-", "\\mbox{-}") for h in hidden]          # keep hyphenated names on one line
    N["HiddenCats"] = (", ".join(hl[:-1]) + " and " + hl[-1]) if len(hl) > 1 else (hl[0] if hl else "none")
    N["NHiddenCats"] = str(len(hidden))
    # rank of each category per method (1 = weakest), printed so the text's ranking claims can be checked
    for j, (_, _, lab) in enumerate(cols):
        order_j = [clist[i] for i in np.argsort(M[:, j])]
        print(f"weakest categories, {lab}: {order_j[:3]}")

    # ---------------- Tables ----------------
    rows = [("LightGBM (EMBER baseline)", "lightgbm"), ("MLP (standard)", "mlp"), ("MLP + PGD-AT", "pgd_at")]
    T = ["\\begin{tabular}{lccccc}", "\\toprule", "Model & Acc. (\\%) & F1 (\\%) & TPR (\\%) & FPR (\\%) & AUC \\\\", "\\midrule"]
    def clean_row(lab, getter):
        vals = [getter(sd) for sd in seeds]
        cells = []
        for k in ("acc", "f1", "tpr", "fpr"):
            m, s = ms([v[k] for v in vals]); cells.append(fmt(m, s, nd=2))
        m, s = ms([v["auc"] for v in vals]); cells.append(fmt(m, s, pct=False, nd=4))
        return f"{lab} & " + " & ".join(cells) + " \\\\"
    for lab, k in rows:
        T.append(clean_row(lab, lambda sd, k=k: sd[k]))
    for k in cfg["keep_list"]:
        T.append(clean_row(f"Group ablation, $k$={k}", lambda sd, k=k: sd["ablation"][str(k)]["clean"]))
    for v, lab in V[2:]:
        T.append(clean_row(lab + f" ($\\epsilon$={te})", lambda sd, v=v: sd["certified_training"][v]["clean"]))
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_clean.tex"), "w").write("\n".join(T))

    T = ["\\begin{tabular}{ll" + "c" * len(eps) + "}", "\\toprule",
         "Model & Threat model & " + " & ".join(f"$\\epsilon$={e}" for e in eps) + " \\\\", "\\midrule"]
    for mname, lab in (("mlp", "Standard MLP"), ("pgd_at", "PGD-AT")):
        for tm in ("unconstrained", "constrained"):
            m, s = ms([sd["attacks"][mname][tm]["pgd"] for sd in seeds])
            T.append(f"{lab} & {tm} & " + " & ".join(fmt(x, y) for x, y in zip(m, s)) + " \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_attacks.tex"), "w").write("\n".join(T))

    nr = len(seeds[0]["ablation"][str(cfg["keep_list"][0])]["cert_tpr"])
    T = ["\\begin{tabular}{lc" + "c" * nr + "}", "\\toprule",
         "$k$ & Views & " + " & ".join(f"$r$={r}" for r in range(nr)) + " \\\\", "\\midrule"]
    for k in cfg["keep_list"]:
        m, s = ms([sd["ablation"][str(k)]["cert_tpr"] for sd in seeds])
        T.append(f"{k} & {seeds[0]['ablation'][str(k)]['n_subsets']} & " + " & ".join(fmt(x, y) for x, y in zip(m, s)) + " \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_group_cert.tex"), "w").write("\n".join(T))

    rpts = [0.0, 0.25, 0.5, 1.0]
    T = ["\\begin{tabular}{llc" + "c" * len(rpts) + "}", "\\toprule",
         "$\\sigma$ & Noise & Clean acc. (\\%) & " + " & ".join(f"$R\\geq${r}" for r in rpts) + " \\\\", "\\midrule"]
    for sg in sig:
        for var in ("isotropic", "subspace"):
            key = f"{var}_{sg}"
            ca, cs = ms([sd["smoothing"][key]["clean_acc"] for sd in seeds])
            cells = [fmt(np.interp(r, radii, curves[key]), 0) for r in rpts]
            T.append(f"{sg} & {var} & {fmt(ca, cs)} & " + " & ".join(cells) + " \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_smoothing.tex"), "w").write("\n".join(T))

    T = ["\\begin{tabular}{l" + "c" * len(ceps) + "c}", "\\toprule",
         "Training & " + " & ".join(f"$\\epsilon$={e}" for e in ceps) + " & Violations \\\\", "\\midrule"]
    for v, lab in V:
        m, s = ms([sd["certified_training"][v]["cert_tpr"] for sd in seeds])
        viol = sum(sd["certified_training"][v]["violations"] for sd in seeds)
        T.append(f"{lab} & " + " & ".join(fmt(x, y) for x, y in zip(m, s)) + f" & {viol} \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_certified_training.tex"), "w").write("\n".join(T))

    # ---------------- numbers.tex ----------------
    def mean(getter):
        return float(np.mean([getter(sd) for sd in seeds]))
    big = lambda n: f"{int(n):,}".replace(",", "{,}")   # thousands separator; {,} also spaces correctly in math mode
    N["NSeeds"] = str(len(seeds))
    N["SeedsNoun"] = "seed" if len(seeds) == 1 else "seeds"
    N["NMutable"] = big(D["n_mutable"]); N["NMonotone"] = str(D["n_monotone"])
    # total feature count, read from the .npy header of X inside the data npz (no need to load the array)
    import zipfile
    with zipfile.ZipFile(cfg["data_npz"]) as zf, zf.open("X.npy") as fh:
        ver = np.lib.format.read_magic(fh)
        rd = np.lib.format.read_array_header_1_0 if ver == (1, 0) else np.lib.format.read_array_header_2_0
        n_feat = rd(fh)[0][1]
    N["NFeatures"] = big(n_feat)
    N["MutablePct"] = f"{D['n_mutable'] / n_feat * 100:.0f}"
    N["NCategories"] = str(D["n_categories"]); N["NFamilies"] = str(D["n_families"])
    N["LgbmAcc"] = f"{mean(lambda s: s['lightgbm']['acc']) * 100:.2f}"
    N["MlpAcc"] = f"{mean(lambda s: s['mlp']['acc']) * 100:.2f}"
    N["MlpGroupEvadeOne"] = f"{(1 - mean(lambda s: s['group_attack_mlp'][1])) * 100:.1f}"
    N["AblOneCleanAcc"] = f"{mean(lambda s: s['ablation']['1']['clean']['acc']) * 100:.2f}"
    N["AblOneCertR"] = f"{mean(lambda s: s['ablation']['1']['cert_tpr'][1]) * 100:.1f}"
    N["AblOneCertRtwo"] = f"{mean(lambda s: s['ablation']['1']['cert_tpr'][2]) * 100:.1f}"
    N["AblViolations"] = str(sum(sd["ablation"][str(k)]["violations"] for sd in seeds for k in cfg["keep_list"]))
    ie = ceps.index(te) if te in ceps else -1
    N["TrainEps"] = str(te)
    N["CrownAsymCert"] = f"{mean(lambda s: s['certified_training']['crownibp_asym']['cert_tpr'][ie]) * 100:.1f}"
    N["CrownAsymCertUnc"] = f"{mean(lambda s: s['certified_training']['crownibp_asym']['cert_tpr_unconstrained'][ie]) * 100:.1f}"
    N["CrownAsymAcc"] = f"{mean(lambda s: s['certified_training']['crownibp_asym']['clean']['acc']) * 100:.2f}"
    ct = lambda v, k, i=ie: mean(lambda s: s['certified_training'][v][k][i]) * 100
    N["CrownSymCert"] = f"{ct('crownibp', 'cert_tpr'):.1f}"
    N["CrownSymCertUnc"] = f"{ct('crownibp', 'cert_tpr_unconstrained'):.1f}"
    N["CrownSymCertTen"] = f"{ct('crownibp', 'cert_tpr', -1):.1f}"
    N["CrownSymCertTenUnc"] = f"{ct('crownibp', 'cert_tpr_unconstrained', -1):.1f}"
    # asymmetric vs symmetric CROWN-IBP: means and seed-to-seed std (population std, as in the tables)
    ctsd = lambda v, i: float(np.std([s['certified_training'][v]['cert_tpr'][i] for s in seeds])) * 100
    N["CrownAsymCertTen"] = f"{ct('crownibp_asym', 'cert_tpr', -1):.1f}"
    N["CrownSymCertStd"] = f"{ctsd('crownibp', ie):.1f}"
    N["CrownAsymCertStd"] = f"{ctsd('crownibp_asym', ie):.1f}"
    N["CrownSymCertTenStd"] = f"{ctsd('crownibp', -1):.1f}"
    N["CrownAsymCertTenStd"] = f"{ctsd('crownibp_asym', -1):.1f}"
    # in how many seeds asym - sym is > 0 at the training budget and < 0 at the largest budget
    def in_seeds(k, n):
        return "in every seed" if k == n else ("in no seed" if k == 0 else f"in {k} of {n} seeds")
    dlt = lambda i: [s['certified_training']['crownibp_asym']['cert_tpr'][i]
                     - s['certified_training']['crownibp']['cert_tpr'][i] for s in seeds]
    N["AsymGainSeeds"] = in_seeds(sum(x > 0 for x in dlt(ie)), len(seeds))
    N["AsymLossTenSeeds"] = in_seeds(sum(x < 0 for x in dlt(-1)), len(seeds))
    N["IbpCert"] = f"{ct('ibp', 'cert_tpr'):.1f}"
    N["CrownSymAcc"] = f"{mean(lambda s: s['certified_training']['crownibp']['clean']['acc']) * 100:.2f}"
    N["CrownSymFpr"] = f"{mean(lambda s: s['certified_training']['crownibp']['clean']['fpr']) * 100:.2f}"
    N["CrownAsymFpr"] = f"{mean(lambda s: s['certified_training']['crownibp_asym']['clean']['fpr']) * 100:.2f}"
    N["StdAccSmall"] = f"{mean(lambda s: s['certified_training']['standard']['clean']['acc']) * 100:.2f}"
    N["AblTwoCertR"] = f"{mean(lambda s: s['ablation']['2']['cert_tpr'][1]) * 100:.1f}"
    N["AblTwoCleanAcc"] = f"{mean(lambda s: s['ablation']['2']['clean']['acc']) * 100:.2f}"
    N["AblThreeCertR"] = f"{mean(lambda s: s['ablation']['3']['cert_tpr'][1]) * 100:.1f}"
    N["AblThreeCleanAcc"] = f"{mean(lambda s: s['ablation']['3']['clean']['acc']) * 100:.2f}"
    N["AblOneEmpR"] = f"{mean(lambda s: s['ablation']['1']['empirical_tpr'][1]) * 100:.1f}"
    N["AblOneEmpRtwo"] = f"{mean(lambda s: s['ablation']['1']['empirical_tpr'][2]) * 100:.1f}"
    sl = sig[-1]
    N["RsSigmaMax"] = str(sl)
    N["RsIsoAccMax"] = f"{mean(lambda s: s['smoothing'][f'isotropic_{sl}']['clean_acc']) * 100:.1f}"
    N["RsSubAccMax"] = f"{mean(lambda s: s['smoothing'][f'subspace_{sl}']['clean_acc']) * 100:.1f}"
    N["NCert"] = big(cfg["n_cert"]); N["NCertPoints"] = big(cfg["n_cert_points"])
    N["StdCert"] =f"{mean(lambda s: s['certified_training']['standard']['cert_tpr'][ie]) * 100:.1f}"
    N["PgdAtCert"] = f"{mean(lambda s: s['certified_training']['pgd_at']['cert_tpr'][ie]) * 100:.1f}"
    s1 = sig[1] if len(sig) > 1 else sig[0]
    N["RsSigma"] = str(s1)
    N["RsIsoAcc"] = f"{mean(lambda s: s['smoothing'][f'isotropic_{s1}']['clean_acc']) * 100:.1f}"
    N["RsSubAcc"] = f"{mean(lambda s: s['smoothing'][f'subspace_{s1}']['clean_acc']) * 100:.1f}"
    N["RsSubHalf"] = f"{np.interp(0.5, radii, curves[f'subspace_{s1}']) * 100:.1f}"
    N["RsIsoHalf"] = f"{np.interp(0.5, radii, curves[f'isotropic_{s1}']) * 100:.1f}"
    N["CTViolations"] = str(sum(sd["certified_training"][v]["violations"] for sd in seeds for v, _ in V))
    mid = eps.index(0.1) if 0.1 in eps else len(eps) // 2
    N["AtkEps"] = str(eps[mid])
    N["MlpPgdCon"] = f"{(1 - mean(lambda s: s['attacks']['mlp']['constrained']['pgd'][mid])) * 100:.1f}"
    N["MlpPgdUnc"] = f"{(1 - mean(lambda s: s['attacks']['mlp']['unconstrained']['pgd'][mid])) * 100:.1f}"
    N["AtPgdCon"] = f"{(1 - mean(lambda s: s['attacks']['pgd_at']['constrained']['pgd'][mid])) * 100:.1f}"
    with open(os.path.join(tdir, "numbers.tex"), "w") as f:
        f.write("% auto-generated by make_figures.py -- do not edit by hand\n")
        for k, v in N.items():
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print("\n".join(f"{k} = {v}" for k, v in N.items()))

    if a.paper:
        import shutil
        for sub in ("figures", "tables"):
            dst = os.path.join(a.paper, sub)
            os.makedirs(dst, exist_ok=True)
            for f in glob.glob(os.path.join(a.res, sub, "*")):
                shutil.copy(f, dst)


if __name__ == "__main__":
    main()
