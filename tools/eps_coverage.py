"""Coverage of the L-infinity certificate (REVISION_PLAN 1h).

    python tools/eps_coverage.py --res <results folder>

For each epsilon: (a) the share of measured in-scope edits whose feature vector lies inside the constrained
box of that radius (from ps_results/edit_files.csv), next to (b) the certified malware detection of the
certified-training models at the same epsilon (from <results folder>/results.json, mean over seeds).
(a) says how much of what an attacker really does the certificate speaks about; (b) says how often it holds.

Writes  ps_results/eps_coverage_vs_certified.csv
        paper/figures/fig_eps_coverage.pdf|png, paper/tables/tab_eps_coverage.tex
"""
import argparse, json, os, sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "ps_results")
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
GRAY = "#8a8985"
plt.rcParams.update({"font.family": "serif", "font.size": 8.5, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.6, "lines.linewidth": 1.6,
                     "lines.markersize": 4, "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight"})
MODELS = [("standard", "Standard"), ("ibp", "IBP"), ("crownibp", "CROWN-IBP")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--res", required=True, help="results folder with certified-training results")
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    a = ap.parse_args()
    D = pd.read_csv(os.path.join(RES, "edit_files.csv"))
    need = np.sort(D[D.scope == "in"].eps_needed.values)
    R = json.load(open(os.path.join(a.res, "results.json")))
    seeds, ceps = list(R["seeds"].values()), R["config"]["cert_eps_list"]
    cert = {m: np.mean([s["certified_training"][m]["cert_tpr"] for s in seeds], 0) for m, _ in MODELS}
    cover = lambda e: float((need <= e).mean())

    rows = [dict(eps=e, edits_inside_box=cover(e), **{"cert_tpr_" + m: float(cert[m][i]) for m, _ in MODELS})
            for i, e in enumerate(ceps)]
    T = pd.DataFrame(rows)
    T.to_csv(os.path.join(RES, "eps_coverage_vs_certified.csv"), index=False)
    print(f"source of certified detection: {a.res} ({R['config']['epochs']} epochs, {len(seeds)} seed(s))")
    print(T.to_string(index=False, float_format=lambda v: f"{v:.3f}"))

    fig, ax = plt.subplots(figsize=(5.2, 2.7))                               # room for the legend beside the axes
    xs = np.logspace(np.log10(min(ceps) / 2), np.log10(max(need.max(), 1) * 1.2), 400)
    ax.plot(xs, [100 * cover(x) for x in xs], "-", color=GRAY, label="Measured edits inside the box")
    for ci, (m, lab) in enumerate(MODELS):
        ax.plot(ceps, cert[m] * 100, "-", color=C[ci], marker="o", label=f"Certified detection, {lab}")
    ax.axvspan(min(ceps), max(ceps), color="#000000", alpha=0.04, lw=0)        # range of evaluated budgets
    ax.set_xscale("log"); ax.set_ylim(-3, 103)
    ax.set_xlabel(r"$\ell_\infty$ budget $\epsilon$ (standardised units)"); ax.set_ylabel("Share (%)")
    ax.legend(fontsize=6.5, loc="center left", bbox_to_anchor=(1.02, 0.5))    # outside: every inside spot is crossed
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(a.paper, "figures", f"fig_eps_coverage.{ext}"))
    plt.close(fig)

    L = ["\\begin{tabular}{lc" + "c" * len(MODELS) + "}", "\\toprule",
         " & Measured edits & \\multicolumn{%d}{c}{Certified malware detection (\\%%)} \\\\" % len(MODELS),
         "\\cmidrule(lr){3-%d}" % (2 + len(MODELS)),
         "$\\epsilon$ & inside the box (\\%) & " + " & ".join(lab for _, lab in MODELS) + " \\\\", "\\midrule"]
    for r in rows:
        L.append(f"{r['eps']} & {100 * r['edits_inside_box']:.1f} & "
                 + " & ".join(f"{100 * r['cert_tpr_' + m]:.1f}" for m, _ in MODELS) + " \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(a.paper, "tables", "tab_eps_coverage.tex"), "w").write("\n".join(L))
    print("wrote fig_eps_coverage and tab_eps_coverage.tex")


if __name__ == "__main__":
    main()
