"""Stage 3e representativeness table: the 30K subset vs all of BODMAS (no training).

    python tools/representativeness.py [--out results_repr]

Class ratio, malware category shares, families covered, malware per month.
Writes <out>/representativeness.csv, <out>/months.csv and paper/tables/tab_representativeness.tex.
"""
import argparse, os, sys
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.config import get_config                     # noqa: E402
from malcert.data import select_subset                    # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results_repr")
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    a = ap.parse_args()
    os.chdir(ROOT)
    os.makedirs(a.out, exist_ok=True)
    sel, y, meta = select_subset(get_config("full"), 0)
    meta = meta.assign(y=y, month=pd.to_datetime(meta["timestamp"], format="mixed", utc=True).dt.strftime("%Y-%m"))
    full, sub = meta, meta.iloc[sel]
    rows = []
    for name, D in (("full BODMAS", full), ("30K subset", sub)):
        m = D[D.y == 1]
        r = {"set": name, "samples": len(D), "malware share": float((D.y == 1).mean()),
             "families": int(m["family"].nunique())}
        for c, v in m["category"].value_counts(normalize=True).items():
            r["cat_" + c] = float(v)
        rows.append(r)
    fam_sub = set(sub[sub.y == 1]["family"])
    rows[0]["full malware in a family present in subset"] = float(full[full.y == 1]["family"].isin(fam_sub).mean())
    R = pd.DataFrame(rows).fillna(0.0)
    R.to_csv(os.path.join(a.out, "representativeness.csv"), index=False)
    M = pd.DataFrame({n: D[D.y == 1]["month"].value_counts(normalize=True) for n, D in (("full", full), ("subset", sub))}).fillna(0).sort_index()
    M.to_csv(os.path.join(a.out, "months.csv"))
    cats = [c for c in R.columns if c.startswith("cat_")]
    cats = sorted(cats, key=lambda c: -R[c].iloc[0])[:6]
    T = ["\\begin{tabular}{l" + "r" * (3 + len(cats)) + "}", "\\toprule",
         "Set & Samples & Malware (\\%) & Families & " + " & ".join(c[4:] + " (\\%)" for c in cats) + " \\\\", "\\midrule"]
    for _, r in R.iterrows():
        T.append(f"{r['set']} & {int(r.samples):,} & {100 * r['malware share']:.1f} & {int(r.families)} & ".replace(",", "{,}")
                 + " & ".join(f"{100 * r[c]:.1f}" for c in cats) + " \\\\")
    T += ["\\bottomrule", "\\end{tabular}",
          f"% max abs difference in monthly malware share: {100 * (M['full'] - M['subset']).abs().max():.2f} points"]
    open(os.path.join(a.paper, "tables", "tab_representativeness.tex"), "w").write("\n".join(T))
    print(R.to_string(index=False, float_format=lambda v: f"{v:.3f}"))
    print("max |monthly malware share difference|: %.2f points" % (100 * (M["full"] - M["subset"]).abs().max()))


if __name__ == "__main__":
    main()
