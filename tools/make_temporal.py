"""Temporal-vs-random comparison for the paper, kept separate from make_figures.py so the
random-split outputs (numbers.tex, tab_*.tex, figures) are never touched.

    python tools/make_temporal.py --rand results_full --temp results_temporal --paper paper

Writes  <paper>/tables/tab_temporal.tex       (table)
        <paper>/tables/numbers_temporal.tex   (\Tmp* macros used by the Results text)
Every comparison phrase in the text ("more than", whether a sentence appears at all) is decided
here from the numbers, so a rerun cannot leave a stale direction claim in the manuscript.
"""
import argparse, json, math, os, sys
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def ms(vals):
    a = np.array(vals, dtype=float)
    return a.mean(0), (a.std(0) if len(a) > 1 else np.zeros_like(a.mean(0)))   # population std, as make_figures


def cell(vals, nd):
    """mean +- std in %; the +- is dropped only when every seed gave exactly the same value
    (np.std of identical floats can return ~1e-16, which would print as a misleading +-0.00)."""
    m, s = ms(vals)
    same = len(set(vals)) == 1
    return f"{m * 100:.{nd}f}" + ("" if same else f"$\\pm${s * 100:.{nd}f}")


def load(d):
    R = json.load(open(os.path.join(d, "results.json")))
    return R["config"], list(R["seeds"].values())


def test_window(cfg_dict, temp_dir):
    """Dates of the temporal train/test windows, recomputed with the run's own split code and checked
    against the categories stored in samples_seed*.npz."""
    from malcert.config import Config
    from malcert.data import select_subset, split_indices
    import pandas as pd
    cfg = Config(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in cfg_dict.items()})
    assert cfg.split == "temporal", f"{temp_dir} is not a temporal run"
    sel, y, meta = select_subset(cfg, 0)
    ts = pd.to_datetime(meta["timestamp"].values[sel], format="mixed", errors="coerce", utc=True)
    assert not ts.isna().any(), "unparseable timestamps in the temporal subset"
    data = dict(y=y[sel], category=meta["category"].values[sel], timestamp=ts)
    sp = split_indices(data, cfg, seed=cfg.seeds[0])
    for s in cfg.seeds:
        z = np.load(os.path.join(temp_dir, f"samples_seed{s}.npz"))
        te = split_indices(data, cfg, seed=s)["te"]
        assert np.array_equal(data["category"][te], z["category"]), f"temporal split mismatch, seed {s}"
    t = ts.values
    d = lambda x: str(np.datetime_as_string(x, unit="D"))
    return d(t[sp["te"]].min()), d(t[sp["te"]].max()), d(t[sp["tr"]].max())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rand", default="results_full")
    ap.add_argument("--temp", default="results_temporal")
    ap.add_argument("--paper", default="paper")
    a = ap.parse_args()
    os.chdir(ROOT)                                   # data paths in the saved config are relative to the repo
    cr, SR = load(a.rand)
    ct, ST = load(a.temp)
    assert cr["split"] == "random" and ct["split"] == "temporal"
    assert len(SR) == len(ST), "the caption uses \\NSeeds for both splits"
    ceps, te_eps = ct["cert_eps_list"], ct["ibp_train_eps"]
    ie = ceps.index(te_eps)

    abl = lambda k: (lambda s: s["ablation"][k]["clean"])
    rows = [("LightGBM", lambda s: s["lightgbm"]),
            ("MLP (standard)", lambda s: s["mlp"]),
            ("MLP + PGD-AT", lambda s: s["pgd_at"]),
            ("Group ablation, $k$=1", abl("1")),
            ("Group ablation, $k$=2", abl("2")),
            ("Group ablation, $k$=3", abl("3")),
            (f"CROWN-IBP ($\\epsilon$={te_eps})", lambda s: s["certified_training"]["crownibp"]["clean"])]
    certabl = lambda k, r: (lambda s: s["ablation"][k]["cert_tpr"][r])
    crows = [(f"Group ablation, $k$={k}", f"$r$={r}", certabl(k, r)) for k in ("1", "2", "3") for r in (1, 2)]
    crows.append(("CROWN-IBP", f"$\\epsilon$={te_eps}", lambda s: s["certified_training"]["crownibp"]["cert_tpr"][ie]))

    # ---------------- table 1: clean metrics ----------------
    sub = ["Acc.", "TPR", "FPR"]
    T = ["\\begin{tabular}{l" + "c" * 6 + "}", "\\toprule",
         " & \\multicolumn{3}{c}{Random split} & \\multicolumn{3}{c}{Temporal split} \\\\",
         "\\cmidrule(lr){2-4}\\cmidrule(lr){5-7}",
         "Model & " + " & ".join(sub + sub) + " \\\\", "\\midrule"]
    for lab, g in rows:
        cells = [cell([g(s)[k] for s in S], nd=2) for S in (SR, ST) for k in ("acc", "tpr", "fpr")]
        T.append(f"{lab} & " + " & ".join(cells) + " \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]

    # ---------------- table 2: certified TPR, with the drop and its std ----------------
    C = ["\\begin{tabular}{llccc}", "\\toprule",
         "Model & Certificate & Random split & Temporal split & Drop \\\\", "\\midrule"]
    for lab, cert_lab, g in crows:
        vr, vt = [g(s) for s in SR], [g(s) for s in ST]
        (mr, sr), (mt, stt) = ms(vr), ms(vt)
        dstd = math.sqrt(sr ** 2 + stt ** 2)
        d = f"{(mr - mt) * 100:.1f}" + ("" if len(set(vr)) == 1 and len(set(vt)) == 1 else f"$\\pm${dstd * 100:.1f}")
        C.append(f"{lab} & {cert_lab} & {cell(vr, 1)} & {cell(vt, 1)} & {d} \\\\")
    C += ["\\bottomrule", "\\end{tabular}"]

    # ---------------- macros ----------------
    N = {}
    t0, t1, trend = test_window(ct, a.temp)
    N["TmpTestStart"], N["TmpTestEnd"], N["TmpTrainEnd"] = t0, t1, trend
    N["TmpCertEps"] = str(te_eps)
    stat = lambda S, g: ms([g(s) for s in S])                       # (mean, std) as fractions
    pts = lambda x: f"{x * 100:.1f}"

    def drop(g):
        (mr, sr), (mt, stt) = stat(SR, g), stat(ST, g)
        return mr - mt, sr, stt

    def compare(g_clean, g_cert):
        """Is the certified drop larger than the clean drop by more than the combined std?"""
        dc, s1, s2 = drop(g_clean)
        dz, s3, s4 = drop(g_cert)
        comb = math.sqrt(s1 ** 2 + s2 ** 2 + s3 ** 2 + s4 ** 2)
        phrase = ("more than" if dz - dc > comb else "less than" if dc - dz > comb else "about as much as")
        return dc, dz, comb, phrase

    abl_tpr = lambda s: s["ablation"]["1"]["clean"]["tpr"]
    abl_c1 = lambda s: s["ablation"]["1"]["cert_tpr"][1]
    cr_tpr = lambda s: s["certified_training"]["crownibp"]["clean"]["tpr"]
    cr_c = lambda s: s["certified_training"]["crownibp"]["cert_tpr"][ie]
    for name, gc, gz in (("Abl", abl_tpr, abl_c1), ("Crown", cr_tpr, cr_c)):
        dc, dz, comb, phrase = compare(gc, gz)
        N[f"Tmp{name}TprDrop"], N[f"Tmp{name}CertDrop"] = pts(dc), pts(dz)
        N[f"Tmp{name}DropStd"], N[f"Tmp{name}CertVsClean"] = pts(comb), phrase
        # std of each drop on its own: sqrt(std_random^2 + std_temporal^2)
        _, sc1, sc2 = drop(gc)
        _, sz1, sz2 = drop(gz)
        N[f"Tmp{name}TprDropStd"] = pts(math.sqrt(sc1 ** 2 + sc2 ** 2))
        N[f"Tmp{name}CertDropStd"] = pts(math.sqrt(sz1 ** 2 + sz2 ** 2))
        N[f"Tmp{name}Gap"] = pts(dz - dc)
        N[f"Tmp{name}GapRatio"] = f"{(dz - dc) / comb:.1f}"         # gap in units of the combined std
        N[f"Tmp{name}DropRatio"] = f"{dz / dc:.1f}"                  # certified drop / clean drop
        N[f"Tmp{name}DropRatioInt"] = f"{round(dz / dc):d}"          # same, as a whole number for "roughly N times"
        print(f"{name}: clean TPR drop {dc*100:.2f}, certified drop {dz*100:.2f}, combined std {comb*100:.2f}, "
              f"gap/std {(dz - dc) / comb:.2f}, drop ratio {dz / dc:.2f} -> {phrase}")
        if name == "Abl" and not 0.5 <= (dz - dc) / comb < 1.5:
            raise SystemExit("results_text.tex says the ablation gap is 'about one' combined std and is not "
                             f"claimed as significant, but it is now {(dz - dc) / comb:.2f} std: rewrite that sentence")
        if name == "Crown" and not dz > dc + comb:
            raise SystemExit("Discussion/Conclusion say CROWN-IBP's certified detection falls several times more "
                             "than its clean detection, which no longer holds: rewrite those sentences")

    # FPR on both splits; the text says it drops on the temporal window for every model
    fpr_get = {"LightGBM": lambda s: s["lightgbm"]["fpr"], "Mlp": lambda s: s["mlp"]["fpr"],
               "PgdAt": lambda s: s["pgd_at"]["fpr"], "Abl": lambda s: s["ablation"]["1"]["clean"]["fpr"],
               "Crown": lambda s: s["certified_training"]["crownibp"]["clean"]["fpr"]}
    n_down = 0
    for name, g in fpr_get.items():
        (fr, _), (ft, _) = stat(SR, g), stat(ST, g)
        n_down += ft < fr
        if name in ("Mlp", "Crown"):
            N[f"Tmp{name}FprRand"], N[f"Tmp{name}FprTemp"] = f"{fr * 100:.2f}", f"{ft * 100:.2f}"
    N["TmpFprDropModels"] = "every model" if n_down == len(fpr_get) else f"{n_down} of {len(fpr_get)} models"

    # accuracy loss, CROWN-IBP vs standard MLP; the sentence appears only if the gap exceeds the combined std
    mlp_acc = lambda s: s["mlp"]["acc"]
    cr_acc = lambda s: s["certified_training"]["crownibp"]["clean"]["acc"]
    for name, g in (("Mlp", mlp_acc), ("Crown", cr_acc)):
        (mr, _), (mt, _) = stat(SR, g), stat(ST, g)
        N[f"Tmp{name}AccRand"], N[f"Tmp{name}AccTemp"] = f"{mr * 100:.2f}", f"{mt * 100:.2f}"
    lm, s1, s2 = drop(mlp_acc)
    lc, s3, s4 = drop(cr_acc)
    comb = math.sqrt(s1 ** 2 + s2 ** 2 + s3 ** 2 + s4 ** 2)
    N["TmpMlpAccLoss"], N["TmpCrownAccLoss"], N["TmpAccLossStd"] = pts(lm), pts(lc), pts(comb)
    print(f"accuracy loss: MLP {lm*100:.2f}, CROWN-IBP {lc*100:.2f}, gap {(lm-lc)*100:.2f}, combined std {comb*100:.2f}")
    N["TmpCrownVsMlpAccSentence"] = (
        "CROWN-IBP also loses less clean accuracy than the standard MLP "
        "(\\TmpCrownAccLoss{} vs.\\ \\TmpMlpAccLoss{} points), a gap larger than their combined "
        "seed-to-seed standard deviation (\\TmpAccLossStd{} points)." if lm - lc > comb else "")

    # malware share of the test set(s): mean over seeds of each seed's test labels
    share = lambda d, cfgd: float(np.mean([np.load(os.path.join(d, f"samples_seed{s}.npz"))["y"].mean()
                                           for s in cfgd["seeds"]])) * 100
    N["TmpMalShareRand"], N["TmpMalShareTemp"] = f"{share(a.rand, cr):.1f}", f"{share(a.temp, ct):.1f}"
    print(f"malware share of test set: random {N['TmpMalShareRand']}, temporal {N['TmpMalShareTemp']}")
    N["TmpMalShareCmp"] = "larger" if share(a.temp, ct) > share(a.rand, cr) else "smaller"
    # TPR is the headline drift metric (FPR falls on the temporal window, which inflates accuracy):
    # the CROWN-IBP vs MLP sentence compares TPR loss and appears only if the gap exceeds the combined std
    mlp_tpr = lambda s: s["mlp"]["tpr"]
    tm, s1, s2 = drop(mlp_tpr)
    tc, s3, s4 = drop(cr_tpr)
    tcomb = math.sqrt(s1 ** 2 + s2 ** 2 + s3 ** 2 + s4 ** 2)
    N["TmpMlpTprLoss"], N["TmpCrownTprLoss"], N["TmpTprLossStd"] = pts(tm), pts(tc), pts(tcomb)
    print(f"TPR loss: MLP {tm*100:.2f}, CROWN-IBP {tc*100:.2f}, gap {(tm-tc)*100:.2f}, combined std {tcomb*100:.2f}")
    N["TmpCrownVsMlpSentence"] = (
        "Under drift, CROWN-IBP loses less malware detection than the standard MLP "
        "(\\TmpCrownTprLoss{} vs.\\ \\TmpMlpTprLoss{} points of TPR), a gap larger than their combined "
        "seed-to-seed standard deviation (\\TmpTprLossStd{} points)." if tm - tc > tcomb else "")

    # ---------------- group ablation across keep sizes ----------------
    # does a larger keep size drift less? k=3 vs k=1, judged against the combined std, for clean TPR and
    # certified TPR at r=1 (k=3 certifies nothing at r>=2, so r=1 is the only radius all k share)
    def cmp_phrase(d_big, d_small, comb):
        return "less than" if d_small - d_big > comb else ("more than" if d_big - d_small > comb else "about as much as")
    kd = {}
    for k in ("1", "2", "3"):
        kd[k] = dict(tpr=drop(lambda s, k=k: s["ablation"][k]["clean"]["tpr"]),
                     cert=drop(lambda s, k=k: s["ablation"][k]["cert_tpr"][1]))
    word = {"1": "One", "2": "Two", "3": "Three"}
    for k in ("2", "3"):
        for m in ("tpr", "cert"):
            dd, s1, s2 = kd[k][m]
            N[f"TmpAbl{word[k]}{'Tpr' if m == 'tpr' else 'Cert'}Drop"] = pts(dd)
            N[f"TmpAbl{word[k]}{'Tpr' if m == 'tpr' else 'Cert'}DropStd"] = pts(math.sqrt(s1 ** 2 + s2 ** 2))
    for m, nm in (("tpr", "Tpr"), ("cert", "Cert")):
        d1, a1, a2 = kd["1"][m]
        d3, b1, b2 = kd["3"][m]
        comb = math.sqrt(a1 ** 2 + a2 ** 2 + b1 ** 2 + b2 ** 2)
        N[f"TmpAblK{nm}Cmp"] = cmp_phrase(d3, d1, comb)
        print(f"ablation {m} drop: k=1 {d1*100:.2f}, k=3 {d3*100:.2f}, combined std {comb*100:.2f} -> k=3 {N[f'TmpAblK{nm}Cmp']} k=1")
    if not (N["TmpAblKTprCmp"] == N["TmpAblKCertCmp"] == "less than"):
        raise SystemExit("results_text.tex says k=3 drifts less than k=1 in both clean and certified detection, "
                         "which no longer holds beyond the combined std: rewrite that sentence")
    dstd = {k: math.sqrt(kd[k]["cert"][1] ** 2 + kd[k]["cert"][2] ** 2) for k in kd}
    if not dstd["2"] > max(dstd["1"], dstd["3"]):
        raise SystemExit("results_text.tex says k=2's certified drop has high variance, but it is no longer "
                         "the largest of the three: rewrite that sentence")
    for m in ("tpr", "cert"):
        lo, hi = sorted((kd["1"][m][0], kd["3"][m][0]))
        if not lo <= kd["2"][m][0] <= hi:
            raise SystemExit(f"results_text.tex says k=2 lies between k=1 and k=3 ({m} drop), which no longer holds")
    cdrops = {k: kd[k]["cert"] for k in kd}
    kmin = min(cdrops, key=lambda k: cdrops[k][0]); kmax = max(cdrops, key=lambda k: cdrops[k][0])
    N["TmpAblCertDropMin"], N["TmpAblCertDropMax"] = pts(cdrops[kmin][0]), pts(cdrops[kmax][0])
    # the Discussion says group ablation's certified detection degrades more than CROWN-IBP's under drift
    dcr, c1, c2 = drop(cr_c)
    dmin, m1, m2 = cdrops[kmin]
    if not dmin - dcr > math.sqrt(c1 ** 2 + c2 ** 2 + m1 ** 2 + m2 ** 2):
        raise SystemExit("Discussion says the group certificate degrades more under drift than CROWN-IBP, "
                         "which no longer holds for every keep size: rewrite that sentence")

    tdir = os.path.join(a.paper, "tables")
    open(os.path.join(tdir, "tab_temporal_clean.tex"), "w").write("\n".join(T))
    open(os.path.join(tdir, "tab_temporal_cert.tex"), "w").write("\n".join(C))
    with open(os.path.join(tdir, "numbers_temporal.tex"), "w") as f:
        f.write("% auto-generated by tools/make_temporal.py -- do not edit by hand\n")
        for k, v in N.items():
            assert k.startswith("Tmp")
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print("\n".join(f"{k} = {v}" for k, v in N.items()))


if __name__ == "__main__":
    main()
