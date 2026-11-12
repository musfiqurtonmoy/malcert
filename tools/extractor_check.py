"""Extractor compatibility checks (REVISION_PLAN 1i.3): are the feature vectors extracted here
(EMBER extractor + LIEF 0.10.1, tools/ps_build.py) comparable with the vectors in BODMAS?

    python tools/extractor_check.py

1. Exact matches: every original corpus file whose SHA-256 is in the BODMAS metadata; its vector here
   is compared with the BODMAS vector, feature by feature.
2. Classification: a LightGBM trained on BODMAS (seed-0 training split, the settings of run_all.py)
   classifies all original corpus files, which are benign Microsoft binaries. A low benign rate would
   mean the vectors are off-distribution for BODMAS-trained models.
3. Range: per feature unit, how many corpus files have a value outside the range of ALL BODMAS rows,
   and outside the 1st-99th percentile band of BODMAS benign files.

Writes ps_results/extractor_check.json, ps_results/extractor_units.csv, paper/tables/numbers_xc.tex (prefix Xc)
"""
import argparse, json, os, sys
from collections import OrderedDict

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.config import get_config                                             # noqa: E402
from malcert.data import FEATURE_UNITS, load_subset, split_indices                # noqa: E402

RES = os.path.join(ROOT, "ps_results")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    a = ap.parse_args()
    os.chdir(ROOT)
    cfg = get_config("full")
    F = np.load(os.path.join(RES, "features.npz"))
    keep = F["edit"] == "orig"
    Xc, names = F["X"][keep], F["fname"][keep]
    corpus = pd.read_csv(os.path.join(RES, "corpus_manifest.csv")).set_index("file").loc[names]
    is32 = np.array([n.startswith("w32__") for n in names])
    out = OrderedDict(n_files=int(len(names)), n_pe32=int(is32.sum()), n_pe32plus=int((~is32).sum()))

    # ---- 1. exact matches with BODMAS ----
    meta = pd.read_csv(cfg.meta_csv)
    Xb = np.load(cfg.data_npz)["X"]                       # the one full-size array of this script
    yb = np.load(cfg.data_npz)["y"]
    pos = {s: i for i, s in enumerate(meta["sha"])}
    matches = []
    for n, s in zip(names, corpus.sha256):
        if s in pos:
            d = Xb[pos[s]].astype(np.float64) != Xc[list(names).index(n)].astype(np.float64)
            matches.append(dict(file=n, bodmas_label=int(yb[pos[s]]), features_differing=int(d.sum()),
                                units_differing=sorted({u for u, a0, b0, _ in FEATURE_UNITS if d[a0:b0].any()})))
    out["bodmas_matches"] = matches
    print(f"corpus files also in BODMAS (SHA-256): {len(matches)} of {len(names)}")
    for m in matches:
        print(f"   {m['file']}: BODMAS label {m['bodmas_label']}, features differing {m['features_differing']} {m['units_differing'] or ''}")

    # ---- 3. range (uses Xb while it is loaded) ----
    lo_all, hi_all = Xb.min(0), Xb.max(0)
    del Xb
    data = load_subset(cfg, seed=0)
    ben = data["X"][data["y"] == 0]
    p1, p99 = np.percentile(ben, 1, axis=0), np.percentile(ben, 99, axis=0)
    out_all = (Xc < lo_all) | (Xc > hi_all)
    out_band = (Xc < p1) | (Xc > p99)
    rows = []
    for u, a0, b0, kind in FEATURE_UNITS:
        rows.append(OrderedDict(unit=u, kind=kind, n_features=b0 - a0,
                                files_outside_bodmas_range=int(out_all[:, a0:b0].any(1).sum()),
                                entries_outside_benign_1_99=float(out_band[:, a0:b0].mean()),
                                entries_outside_benign_1_99_pe32=float(out_band[is32][:, a0:b0].mean()) if is32.any() else np.nan,
                                entries_outside_benign_1_99_pe32plus=float(out_band[~is32][:, a0:b0].mean())))
    U = pd.DataFrame(rows)
    U.to_csv(os.path.join(RES, "extractor_units.csv"), index=False)
    far = U[U.files_outside_bodmas_range > 0]
    out["files_with_any_feature_outside_bodmas_range"] = int(out_all.any(1).sum())
    out["units_with_a_file_outside_bodmas_range"] = {r.unit: int(r.files_outside_bodmas_range) for r in far.itertuples()}
    out["entries_outside_benign_1_99_band"] = float(out_band.mean())       # 2% expected for BODMAS benign itself
    print(f"\nfiles with any feature outside the range of all BODMAS rows: {out['files_with_any_feature_outside_bodmas_range']}")
    print("   units:", out["units_with_a_file_outside_bodmas_range"] or "none")
    print(f"feature entries outside the BODMAS-benign 1-99% band: {100 * out_band.mean():.2f}% "
          "(a BODMAS benign file has 2% by construction, less for constant features)")
    worst = U.sort_values("entries_outside_benign_1_99", ascending=False).head(8)
    print(worst[["unit", "n_features", "entries_outside_benign_1_99", "entries_outside_benign_1_99_pe32",
                 "entries_outside_benign_1_99_pe32plus"]].to_string(index=False, float_format=lambda v: f"{v:.3f}"))

    # ---- 2. classification by a BODMAS-trained LightGBM ----
    import lightgbm as lgb
    sp = split_indices(data, cfg, seed=0)
    gbm = lgb.LGBMClassifier(n_estimators=500, num_leaves=64, learning_rate=0.05, random_state=0, verbose=-1)
    gbm.fit(data["X"][sp["tr"]], data["y"][sp["tr"]])
    te = sp["te"]
    s_te = gbm.predict_proba(data["X"][te])[:, 1]
    yte = data["y"][te]
    s = gbm.predict_proba(Xc)[:, 1]
    out["lightgbm"] = OrderedDict(
        bodmas_test_acc=float(((s_te >= 0.5) == yte).mean()), bodmas_test_fpr=float((s_te[yte == 0] >= 0.5).mean()),
        corpus_benign_rate=float((s < 0.5).mean()), corpus_benign_rate_pe32plus=float((s[~is32] < 0.5).mean()),
        corpus_benign_rate_pe32=float((s[is32] < 0.5).mean()) if is32.any() else None,
        corpus_score_median=float(np.median(s)), corpus_score_max=float(s.max()),
        flagged=sorted(str(n) for n in names[s >= 0.5]))
    L = out["lightgbm"]
    print(f"\nLightGBM trained on BODMAS: test accuracy {100 * L['bodmas_test_acc']:.2f}%, test FPR {100 * L['bodmas_test_fpr']:.2f}%")
    print(f"corpus classified benign: {100 * L['corpus_benign_rate']:.1f}% (PE32+ {100 * L['corpus_benign_rate_pe32plus']:.1f}%, "
          f"PE32 {100 * (L['corpus_benign_rate_pe32'] or 0):.1f}%); median score {L['corpus_score_median']:.4f}; flagged: {L['flagged'] or 'none'}")

    json.dump(out, open(os.path.join(RES, "extractor_check.json"), "w"), indent=1)
    N = OrderedDict()
    N["XcNMatches"] = str(len(matches)); N["XcNMatchesIdentical"] = str(sum(m["features_differing"] == 0 for m in matches))
    N["XcBenignRate"] = f"{100 * L['corpus_benign_rate']:.1f}"
    N["XcBenignRateSixtyFour"] = f"{100 * L['corpus_benign_rate_pe32plus']:.1f}"
    N["XcBenignRateThirtyTwo"] = f"{100 * (L['corpus_benign_rate_pe32'] or 0):.1f}"
    N["XcBodmasFpr"] = f"{100 * L['bodmas_test_fpr']:.2f}"
    N["XcNFilesOutsideRange"] = str(out["files_with_any_feature_outside_bodmas_range"])
    N["XcOutsideBandPct"] = f"{100 * out_band.mean():.1f}"
    with open(os.path.join(a.paper, "tables", "numbers_xc.tex"), "w") as f:
        f.write("% auto-generated by tools/extractor_check.py -- do not edit by hand\n")
        for k, v in N.items():
            assert k.startswith("Xc") and k.isalpha(), k
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(f"\nwrote extractor_check.json, extractor_units.csv and {len(N)} macros")


if __name__ == "__main__":
    main()
