"""Runtime table (REVISION_PLAN 2f) from the `cost` records of a results.json (mean over seeds).

    python tools/make_runtime.py --res <results folder> [--paper paper]

Writes paper/tables/tab_runtime.tex: per model, training wall-clock (s), certification time per sample (ms)
and forward passes per sample, on the machine named in the results' provenance.
"""
import argparse, json, os
import numpy as np

LABELS = {"lightgbm": "LightGBM (EMBER reference)", "lightgbm_mono": "LightGBM, monotonic (Incer et al.)",
          "ablation_main": "Group ablation, main (MLP views)", "ablation_second": "Group ablation, second (MLP views)",
          "ablation_ember": "Group ablation, EMBER groups (MLP views)",
          "ablation_lgbm_main": "Group ablation, main (LightGBM views)",
          "giri_reimpl": "Giri et al., re-implementation", "ct_standard": "Standard MLP (certified training block)",
          "ct_pgd_at": "PGD-AT", "ct_crownibp": "CROWN-IBP, constrained box",
          "ct_crownibp_unc": "CROWN-IBP, unconstrained ball"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--res", required=True)
    ap.add_argument("--paper", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paper"))
    a = ap.parse_args()
    R = json.load(open(os.path.join(a.res, "results.json")))
    seeds = list(R["seeds"].values())
    dev = R["provenance"][0]["device_name"]
    T = ["\\begin{tabular}{lrrr}", "\\toprule", "Model & Training (s) & Certification (ms/sample) & Forward passes/sample \\\\",
         "\\midrule"]
    for k, lab in LABELS.items():
        rows = [s["cost"][k] for s in seeds if k in s.get("cost", {})]
        if not rows:
            continue
        tr = np.mean([r["train_seconds"] for r in rows])
        ce = [r["cert_ms_per_sample"] for r in rows if r["cert_ms_per_sample"] is not None]
        fp = rows[0]["forward_passes_per_sample"]
        T.append(f"{lab} & {tr:.0f} & {np.mean(ce):.3f} & {fp if fp is not None else '1 bound pass'} \\\\"
                 if ce else f"{lab} & {tr:.0f} & -- & -- \\\\")
    T += ["\\bottomrule", "\\end{tabular}", f"% {a.res}: {len(seeds)} seed(s), {R['config']['epochs']} epochs, {dev}"]
    open(os.path.join(a.paper, "tables", "tab_runtime.tex"), "w").write("\n".join(T))
    print("\n".join(T))


if __name__ == "__main__":
    main()
