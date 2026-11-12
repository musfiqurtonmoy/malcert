"""Epsilon in real units (REVISION_PLAN 1f, comment Am2).

    python tools/eps_units.py

The L-infinity budget epsilon is measured in standardised units: z = (slog1p(x) - mean) / std with the
BODMAS training statistics (seed 0). For readable features of the MEDIAN test malware sample (seed 0),
this script inverts that transform and reports the raw change an epsilon of 0.01, 0.05 and 0.1 allows,
and the epsilon that one more unit (one section, one import, one string, 1 KB) needs.
If the problem-space check has run, it also lists the epsilon each real edit needed (ps_results/edit_map.csv).

Writes  ps_results/eps_units.csv, paper/tables/tab_eps_units.tex, paper/tables/numbers_eps.tex (prefix Eu)
"""
import argparse, os, sys
from collections import OrderedDict

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.config import get_config                                             # noqa: E402
from malcert.data import Preprocessor, load_subset, split_indices, unit_index     # noqa: E402

RES = os.path.join(ROOT, "ps_results")
EPS = (0.01, 0.05, 0.1)
# (macro stem, table label, unit name or feature index, unit of one step, size of one step)
FEATS = [("Size", "File size (bytes)", "General.size", "1 KB", 1024.0),
         ("Strings", "Printable strings", "Strings.numstrings", "1 string", 1.0),
         ("Imports", "Imported functions", "General.imports", "1 import", 1.0),
         ("Sections", "Sections", "Section.n_sections", "1 section", 1.0),
         ("ByteBin", "Byte-histogram bin 0x00 (share of bytes)", 0, "0.01 of all bytes", 0.01)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    a = ap.parse_args()
    os.chdir(ROOT)
    cfg = get_config("full")
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=0)
    pp = Preprocessor().fit(data["X"][sp["tr"]])
    Xte, yte = data["X"][sp["te"]].astype(np.float64), data["y"][sp["te"]]
    med = np.median(Xte[yte == 1], axis=0)                 # median test malware (the attacked class), per feature
    uidx = unit_index()
    rows, N = [], OrderedDict()
    N["EuNMalware"] = f"{int((yte == 1).sum()):,}".replace(",", "{,}")
    for stem, label, key, step_name, step in FEATS:
        i = key if isinstance(key, int) else uidx[key][0]
        x, sd = float(med[i]), float(pp.sd[i])
        row = OrderedDict(feature=label, index=i, median_raw=x, std_of_log=sd)
        for e in EPS:
            up = np.expm1(np.log1p(x) + e * sd) - x        # largest increase the box [z, z + eps] allows
            row[f"increase_at_eps_{e}"] = up
            row[f"increase_pct_at_eps_{e}"] = 100 * up / x if x > 0 else float("nan")
        row["one_step"] = step_name
        row["eps_for_one_step"] = (np.log1p(x + step) - np.log1p(x)) / sd
        rows.append(row)
        N[f"Eu{stem}Median"] = fmt(x)
        N[f"Eu{stem}IncTenth"] = fmt(row["increase_at_eps_0.1"])
        N[f"Eu{stem}IncTenthPct"] = f"{row['increase_pct_at_eps_0.1']:.1f}"
        N[f"Eu{stem}EpsOneStep"] = f"{row['eps_for_one_step']:.2g}"
    R = pd.DataFrame(rows)
    os.makedirs(RES, exist_ok=True)
    R.to_csv(os.path.join(RES, "eps_units.csv"), index=False)
    pd.set_option("display.width", 220)
    print(R.to_string(index=False, float_format=lambda v: f"{v:.4g}"))

    T = ["\\begin{tabular}{lr" + "r" * len(EPS) + "lr}", "\\toprule",
         " & Median & \\multicolumn{%d}{c}{Largest increase allowed by $\\epsilon$} & \\multicolumn{2}{c}{$\\epsilon$ needed for} \\\\" % len(EPS),
         "\\cmidrule(lr){3-%d}\\cmidrule(lr){%d-%d}" % (2 + len(EPS), 3 + len(EPS), 4 + len(EPS)),
         "Feature & value & " + " & ".join(f"$\\epsilon$={e}" for e in EPS) + " & one more & $\\epsilon$ \\\\", "\\midrule"]
    for r in rows:
        T.append(f"{r['feature']} & {fmt(r['median_raw'])} & "
                 + " & ".join(fmt(r[f'increase_at_eps_{e}']) for e in EPS)
                 + f" & {r['one_step']} & {r['eps_for_one_step']:.2g} \\\\")
    em = os.path.join(RES, "edit_map.csv")
    if os.path.exists(em):
        M = pd.read_csv(em)
        M = M[(M.variant == "all") & (M.scope == "in") & (M.get("arch", "all") == "all")]
        T += ["\\midrule", "\\multicolumn{%d}{l}{\\emph{$\\epsilon$ needed by the measured edits (median; 90th percentile)}} \\\\" % (4 + len(EPS))]
        for r in M.itertuples():
            T.append(f"\\multicolumn{{{2 + len(EPS)}}}{{l}}{{\\quad {r.edit.replace('_', ' ')}}} & "
                     f"\\multicolumn{{2}}{{r}}{{{r.eps_median:.2g}; {r.eps_p90:.2g}}} \\\\")
        N["EuEditEpsMin"] = f"{M.eps_median.min():.2g}"
        N["EuEditEpsMax"] = f"{M.eps_median.max():.2g}"
    T += ["\\bottomrule", "\\end{tabular}"]
    tdir = os.path.join(a.paper, "tables")
    open(os.path.join(tdir, "tab_eps_units.tex"), "w").write("\n".join(T))
    with open(os.path.join(tdir, "numbers_eps.tex"), "w") as f:
        f.write("% auto-generated by tools/eps_units.py -- do not edit by hand\n")
        for k, v in N.items():
            assert k.startswith("Eu") and k.isalpha(), k
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(f"\nwrote tab_eps_units.tex and {len(N)} macros")


def fmt(v):
    """Readable number: thousands separators for large values, 2-3 significant digits for small ones."""
    if v >= 100:
        return f"{v:,.0f}".replace(",", "{,}")
    if v >= 1:
        return f"{v:.1f}"
    return f"{v:.2g}"


if __name__ == "__main__":
    main()
