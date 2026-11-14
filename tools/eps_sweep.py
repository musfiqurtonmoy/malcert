"""Stage 3g: uniform-ball CROWN-IBP epsilon sweep, the fairness check for the C3 comparison (REVISION_LOG 3-16).

    python tools/eps_sweep.py --radius                       # containment radius eps_f per family and seed only
    python tools/eps_sweep.py [--seeds 0,1,2,3,4] [--out results_eps_sweep]          # the sweep (resumable)
    python tools/eps_sweep.py --analyse [--out results_eps_sweep] [--paper paper]    # summary, comparison, figure, macros

Training uses exactly the settings of `crownibp_unc` in run_all.py's certified block (full preset, family split,
MLP ibp_hidden, ibp_epochs, warm-up and ramp, the uniform L-inf ball without natural bounds); only eps_train varies.
Each (seed, eps) model is trained from torch seed 1,000,003 * seed + 100 + index of eps, so a model does not depend
on which others ran. Nothing is selected from the sweep.

Containment radius eps_f: the smallest uniform eps whose ball contains T_f(1), i.e. the largest |interval endpoint|
of the family's set in standardised units (it depends on the seed's standardisation sd).

Per (seed, eps): clean metrics, collapse flag (one class predicted for every test sample), certified detection over
T_f(t) per family and t (run_all.family_report), certified detection at its own eps_train on the uniform ball.
Writes <out>/results.json after every model, <out>/log.txt; --analyse writes <out>/sweep_summary.csv,
<out>/accuracy_matched.csv, paper/figures/fig_eps_sweep.pdf and paper/tables/numbers_sweep.tex (macros Sw...).
"""
import argparse, json, os, sys, time
import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import run_all                                                                    # noqa: E402
from malcert.attacks import Constraints                                          # noqa: E402
from malcert.config import get_config                                            # noqa: E402
from malcert.data import FAMILIES, Preprocessor, load_subset, split_indices, threat_masks   # noqa: E402
from malcert.models import MLP, load_families                                   # noqa: E402
from malcert.train import fit                                                    # noqa: E402

EPS_GRID = (0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 4.0)       # plus max eps_f of the seed (rounded to 0.1) when larger
EDIT_RUNS = ("results_family", "results_family_s34")


def setup(cfg, seed, dev):
    """Data, standardisation and constraint sets exactly as run_all.run_seed builds them."""
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=seed)
    pp = Preprocessor().fit(data["X"][sp["tr"]])
    T = lambda a, dt=torch.float32: torch.as_tensor(a, dtype=dt, device=dev)
    Xtr, Xte = T(pp.transform(data["X"][sp["tr"]])), T(pp.transform(data["X"][sp["te"]]))
    ytr, yte = T(data["y"][sp["tr"]], torch.long), T(data["y"][sp["te"]], torch.long)
    mutable, monotone = threat_masks()
    zlo, zhi = pp.bounds()
    Ccon = Constraints(mutable, monotone, zlo, zhi, dev, constrained=True)
    Cunc = Constraints(mutable, monotone, zlo, zhi, dev, constrained=False)
    return pp, Xtr, ytr, Xte, yte, data["y"][sp["te"]], Ccon, Cunc


def radii(pp):
    """eps_f per family: largest |endpoint| of T_f(1) in standardised units (0 off the support)."""
    fams = load_families(pp.sd, "cpu")
    return {f: float(torch.maximum(lo.abs(), hi.abs()).max()) for f, (lo, hi) in fams.items()}


def radius_feature(data_dir, seed=0):
    """The feature that sets the largest containment radius (seed 0): its unit name (LaTeX-escaped), the number of
    training files in which it is non-zero, and its training sd in signed-log units."""
    from malcert.data import FEATURE_UNITS
    cfg = get_config("full", split="family", data_npz=os.path.join(data_dir, "bodmas.npz"),
                     meta_csv=os.path.join(data_dir, "bodmas_metadata.csv"),
                     cat_csv=os.path.join(data_dir, "bodmas_malware_category.csv"))
    data = load_subset(cfg, seed=0)
    Xtr = data["X"][split_indices(data, cfg, seed=seed)["tr"]]
    pp = Preprocessor().fit(Xtr)
    best = max(((float(torch.maximum(lo.abs(), hi.abs()).max()), int(torch.maximum(lo.abs(), hi.abs()).argmax()))
                for lo, hi in load_families(pp.sd, "cpu").values()))
    i = best[1]
    unit = next(n for n, s, e, k in FEATURE_UNITS if s <= i < e)
    return unit.replace("_", r"\_"), int((Xtr[:, i] != 0).sum()), float(pp.sd[i])


def sweep(a, cfg, dev):
    os.makedirs(a.out, exist_ok=True)
    res_path = os.path.join(a.out, "results.json")
    R = json.load(open(res_path)) if os.path.exists(res_path) else {"config": run_all.config_json(cfg), "runs": [],
                                                                      "seeds": {}}
    sha = run_all.code_fingerprint()
    if R["runs"] and any(r["code_sha256"] != sha for r in R["runs"]):
        raise SystemExit(f"{res_path} was produced by different code: use a new --out")
    if run_all.config_diff(R["config"], run_all.config_json(cfg)):
        raise SystemExit(f"{res_path} was produced with a different configuration: use a new --out")
    R["runs"].append(dict(code_sha256=sha, git_commit=run_all.git_commit(), git_dirty=run_all.git_dirty(),
                          argv=sys.argv[1:], started=time.ctime(), device=torch.cuda.get_device_name(0)
                          if dev.type == "cuda" else "cpu", epochs_override=a.epochs))
    logf = open(os.path.join(a.out, "log.txt"), "a")

    def log(msg):
        print(msg, flush=True); logf.write(msg + "\n"); logf.flush()

    log(f"=== eps sweep | seeds {cfg.seeds} | eps {a.eps or 'grid + max eps_f'} | epochs {a.epochs or cfg.ibp_epochs} "
        f"| commit {(run_all.git_commit() or 'none')[:7]} | {time.ctime()} ===")
    for seed in cfg.seeds:
        t_seed = time.time()
        pp, Xtr, ytr, Xte, yte, yte_np, Ccon, Cunc = setup(cfg, seed, dev)
        rad = radii(pp)
        S = R["seeds"].setdefault(str(seed), {"radius": rad, "models": {}})
        S["radius"] = rad
        grid = list(a.eps) if a.eps else list(EPS_GRID)
        emax = max(rad.values())
        if not a.eps and emax > max(grid):           # plan 3g.2: max eps_f is trained; a collapse is recorded as such
            grid.append(round(emax, 1))
        log(f"seed {seed}: containment radius " + ", ".join(f"{f} {r:.3f}" for f, r in rad.items()) +
            f"; grid {grid}")
        fams = load_families(pp.sd, dev)
        d = Xtr.shape[1]
        for i, eps in enumerate(grid):
            key = f"{eps:g}"
            if key in S["models"]:
                log(f"  eps {key}: already done, skipped"); continue
            torch.manual_seed(1_000_003 * seed + 100 + i)
            t1 = time.time()
            cert = dict(eps=eps, mask=Cunc.mask, mono=Cunc.mono, zlo=Cunc.zlo, zhi=Cunc.zhi, asym=False)
            m = fit(MLP(d, cfg.ibp_hidden).to(dev), Xtr, ytr, cfg, mode="crownibp", cert=cert,
                    epochs=a.epochs or cfg.ibp_epochs, seed=seed, log=lambda *_: None)
            tr_s = time.time() - t1
            s = run_all.predict(m, Xte)
            pred = s >= 0.5
            own = run_all.verify(m, Xte, yte, eps, Cunc)
            fr = run_all.family_report(m, Xte, yte_np, fams, cfg.family_scales, Ccon.zlo, Ccon.zhi, dev)
            S["models"][key] = dict(eps_train=eps, clean=run_all.metrics(yte_np, pred, s),
                                    collapsed=bool(pred.all() or (~pred).all()),
                                    cert_own_eps=float(own[yte_np == 1].mean()), family_cert=fr,
                                    family_scales=list(cfg.family_scales), train_seconds=round(tr_s, 1),
                                    seconds=round(time.time() - t1, 1))
            run_all.write_atomic(res_path, lambda f: json.dump(R, f, indent=1))
            c = S["models"][key]
            log(f"  eps {key}: acc {c['clean']['acc']:.4f} fpr {c['clean']['fpr']:.4f} collapsed {c['collapsed']} "
                f"cert@own {c['cert_own_eps']:.4f} cert T_f(1) mean {fr['mean_over_families_t1']:.4f} "
                f"({c['seconds']:.0f}s)")
        log(f"seed {seed} done in {time.time() - t_seed:.0f}s")


def analyse(a):
    import pandas as pd
    from scipy import stats as st
    R = json.load(open(os.path.join(a.out, "results.json")))
    rows = []
    for seed, S in R["seeds"].items():
        for key, c in S["models"].items():
            fc = c["family_cert"]; i1 = c["family_scales"].index(1.0)
            rows.append(dict(seed=int(seed), eps=c["eps_train"], acc=c["clean"]["acc"], fpr=c["clean"]["fpr"],
                             collapsed=c["collapsed"], cert_own=c["cert_own_eps"],
                             cert_t1_mean=fc["mean_over_families_t1"],
                             **{f"cert_t1_{f}": fc[f][i1] for f in FAMILIES}))
    D = pd.DataFrame(rows)
    E = []
    for res in EDIT_RUNS:
        p = os.path.join(ROOT, res, "results.json")
        if os.path.exists(p):
            for seed, s in json.load(open(p))["seeds"].items():
                ce = s["certified_training"]["crownibp_edit"]
                fc = ce["family_cert"]; i1 = ce["family_scales"].index(1.0)
                E.append(dict(seed=int(seed), acc=ce["clean"]["acc"], fpr=ce["clean"]["fpr"],
                              cert_t1_mean=fc["mean_over_families_t1"], **{f"cert_t1_{f}": fc[f][i1] for f in FAMILIES}))
    E = pd.DataFrame(E).set_index("seed").sort_index()
    M = D.groupby("eps").agg(n_seeds=("seed", "size"), acc=("acc", "mean"), fpr=("fpr", "mean"),
                             collapsed=("collapsed", "sum"), cert_own=("cert_own", "mean"),
                             cert_t1_mean=("cert_t1_mean", "mean"),
                             **{f"cert_t1_{f}": (f"cert_t1_{f}", "mean") for f in FAMILIES}).reset_index()
    M.to_csv(os.path.join(a.out, "sweep_summary.csv"), index=False)
    rad = pd.DataFrame({int(s): S["radius"] for s, S in R["seeds"].items()}).T
    # accuracy-matched comparison (log 3-16): eps whose mean clean accuracy is closest to edit-aware's; ties: larger eps
    ea = E.acc.mean()
    M["gap"] = (M.acc - ea).abs()
    best = M.sort_values(["gap", "eps"], ascending=[True, False]).iloc[0]
    sw = D[D.eps == best.eps].set_index("seed").cert_t1_mean
    idx = sw.index.intersection(E.index)
    diff = E.cert_t1_mean.loc[idx] - sw.loc[idx]
    n = len(diff); m = diff.mean(); s = diff.std(ddof=1) if n > 1 else 0.0
    h = st.t.ppf(0.975, n - 1) * s / np.sqrt(n) if n > 1 else 0.0
    p = st.ttest_rel(E.cert_t1_mean.loc[idx], sw.loc[idx]).pvalue if n > 1 else float("nan")
    C = pd.DataFrame([dict(matched_eps=best.eps, edit_acc=ea, sweep_acc=best.acc, n_seeds=n, mean_diff=m,
                           ci_lo=m - h, ci_hi=m + h, p=p)])
    C.to_csv(os.path.join(a.out, "accuracy_matched.csv"), index=False)
    print(M.round(4).to_string(index=False)); print(C.round(4).to_string(index=False))
    # figure
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5.5, 3.2))
    ax.plot(M.eps, 100 * M.acc, "o-", label="clean accuracy (uniform-ball)")
    ax.plot(M.eps, 100 * M.cert_t1_mean, "s-", label=r"certified over $T_f(1)$ (uniform-ball)")
    ax.axhline(100 * ea, ls=":", c="C0", lw=1); ax.axhline(100 * E.cert_t1_mean.mean(), ls=":", c="C1", lw=1)
    ax.plot([], [], ":", c="gray", label="edit-aware CROWN-IBP (reference)")
    ax.set_xscale("log"); ax.set_xlabel(r"$\varepsilon_{\mathrm{train}}$"); ax.set_ylabel("%"); ax.set_ylim(0, 100)
    ax.legend(fontsize=7, loc="lower left"); fig.tight_layout()
    fig.savefig(os.path.join(a.paper, "figures", "fig_eps_sweep.pdf")); plt.close(fig)
    # macros
    word = {"F_content": "Content", "F_section": "Section", "F_import": "Import", "F_strip": "Strip"}
    N = {f"SwRadius{word[f]}": f"{rad[f].mean():.2f}" for f in FAMILIES}
    N["SwRadiusMax"] = f"{rad.max(axis=1).mean():.2f}"
    N["SwNSeeds"] = str(int(D.seed.nunique()))
    N["SwBestCertTOne"] = f"{100 * M.cert_t1_mean.max():.1f}"
    N["SwBestCertTOneEps"] = f"{M.loc[M.cert_t1_mean.idxmax(), 'eps']:g}"
    N["SwNCollapsed"] = str(int(D.collapsed.sum()))
    N["SwMatchedEps"] = f"{best.eps:g}"; N["SwMatchedAcc"] = f"{100 * best.acc:.1f}"
    N["SwMatchedDiff"], N["SwMatchedLo"], N["SwMatchedHi"] = (f"{100 * m:.1f}", f"{100 * (m - h):.1f}", f"{100 * (m + h):.1f}")
    N["SwMatchedP"] = f"{p:.3f}" if p >= 0.001 else "<0.001"
    # C3 wording (REVISION_PLAN "3g result and C3 wording")
    pct = lambda v: f"{100 * v:.1f}"
    N["SwEditCert"], N["SwEditFpr"], N["SwEditAcc"] = pct(E.cert_t1_mean.mean()), pct(E.fpr.mean()), pct(E.acc.mean())
    one = M[M.eps == 1.0].iloc[0]
    N["SwUnifOneCert"], N["SwUnifOneFpr"], N["SwUnifOneAcc"] = pct(one.cert_t1_mean), pct(one.fpr), pct(one.acc)
    for f in FAMILIES:
        N[f"SwEdit{word[f]}"], N[f"SwUnifOne{word[f]}"] = pct(E[f"cert_t1_{f}"].mean()), pct(one[f"cert_t1_{f}"])
    # "at FPR near 1%": uniform-ball models whose mean FPR does not exceed edit-aware's mean FPR (matched FPR)
    low = M[M.fpr <= E.fpr.mean()]
    lb = low.sort_values(["cert_t1_mean", "eps"], ascending=[False, False]).iloc[0]
    N["SwUnifLowFprCert"], N["SwUnifLowFprEps"], N["SwUnifLowFprFpr"] = pct(lb.cert_t1_mean), f"{lb.eps:g}", pct(lb.fpr)
    # best uniform eps by certified detection over T_f(1), chosen after the fact (descriptive, favours the baseline)
    bw = D[D.eps == M.loc[M.cert_t1_mean.idxmax(), "eps"]].set_index("seed").cert_t1_mean
    j = bw.index.intersection(E.index)
    db = E.cert_t1_mean.loc[j] - bw.loc[j]
    mb, hb = db.mean(), st.t.ppf(0.975, len(db) - 1) * db.std(ddof=1) / np.sqrt(len(db))
    N["SwBestDiff"], N["SwBestLo"], N["SwBestHi"] = pct(mb), pct(mb - hb), pct(mb + hb)
    N["SwBestP"] = f"{st.ttest_rel(E.cert_t1_mean.loc[j], bw.loc[j]).pvalue:.2f}"
    col = M[M.collapsed == M.n_seeds]
    N["SwCollapseEps"] = f"{col.eps.min():g}" if len(col) else "none"
    N["SwNModels"] = str(len(D))
    unit, nz, sd = radius_feature(a.data_dir)
    N["SwRadiusUnit"], N["SwRadiusUnitNTrain"], N["SwRadiusSectionSd"] = unit, str(nz), f"{sd:.5f}"
    with open(os.path.join(a.paper, "tables", "numbers_sweep.tex"), "w") as f:
        f.write("% auto-generated by tools/eps_sweep.py --analyse -- do not edit by hand\n")
        for k, v in N.items():
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--eps", default=None, help="comma-separated eps_train values instead of the grid (smoke tests)")
    ap.add_argument("--epochs", type=int, default=None, help="override ibp_epochs (smoke tests only)")
    ap.add_argument("--out", default="results_eps_sweep")
    ap.add_argument("--radius", action="store_true", help="only print the containment radius per family and seed")
    ap.add_argument("--analyse", action="store_true")
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    ap.add_argument("--data_dir", default=os.path.join(ROOT, "data"))
    a = ap.parse_args()
    a.eps = [float(e) for e in a.eps.split(",")] if a.eps else None
    if a.analyse:
        return analyse(a)
    seeds = tuple(int(s) for s in a.seeds.split(","))
    cfg = get_config("full", split="family", eval_split="test", seeds=seeds, out_dir=a.out,
                     data_npz=os.path.join(a.data_dir, "bodmas.npz"),
                     meta_csv=os.path.join(a.data_dir, "bodmas_metadata.csv"),
                     cat_csv=os.path.join(a.data_dir, "bodmas_malware_category.csv"))
    if a.radius:
        for seed in seeds:
            data = load_subset(cfg, seed=0)
            sp = split_indices(data, cfg, seed=seed)
            r = radii(Preprocessor().fit(data["X"][sp["tr"]]))
            print(f"seed {seed}: " + ", ".join(f"{f} {v:.3f}" for f, v in r.items()) + f"; max {max(r.values()):.3f}")
        return
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    sweep(a, cfg, dev)


if __name__ == "__main__":
    main()
