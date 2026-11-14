"""Rerun every experiment and rebuild every table, figure and macro of the paper (REVISION_PLAN 4b).

    python reproduce.py                    # unit tests, all Stage 3 runs (~8 h on a GTX 1050 Ti), all analyses, zip
    python reproduce.py --analysis-only    # tables, figures and macros from the results folders already present
    python reproduce.py --problem-space --ps-python <malcert-ps python>   # also redo the problem-space measurement
    python reproduce.py --tuning           # also redo grouping selection and the validation grids

Run it from the repository root with the `malcert` environment's python. Every step is printed before it runs and
the script stops at the first failure. Training runs are resumable: rerunning the script skips finished seeds and
blocks. See reproduce.md for the data download, environments and expected run times.
"""
import argparse, os, subprocess, sys, time, zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

RUNS = [  # Stage 3 (REVISION_LOG 3-9, 3-10, 3-17): (out_dir, arguments)
    ("results_family", "--preset full --split family --seeds 0,1,2"),
    ("results_family_s34", "--preset full --split family --seeds 3,4 --blocks clean,attacks,ablation,certified"),
    ("results_random", "--preset full --split random --seeds 0,1,2 --blocks clean,attacks,ablation,certified"),
    ("results_cut_2019-12", "--preset full --split cutoff --cutoff 2019-12 --seeds 0,1,2 --blocks clean,ablation,certified"),
    ("results_cut_2020-04", "--preset full --split cutoff --cutoff 2020-04 --seeds 0,1,2 --blocks clean,ablation,certified"),
    ("results_fulldata", "--preset full --split family --seeds 0 --full_data --ablation_only_main --blocks clean,ablation"),
]
TESTS = ["test_soundness", "test_threat_model", "test_certificate", "test_split", "test_families"]
ANALYSIS = [
    "tools/leakage_audit.py",
    "tools/representativeness.py",
    "tools/stats.py --family results_family results_family_s34 --random results_random",
    "tools/temporal_decay.py --runs results_cut_2019-12 results_cut_2020-04",
    "tools/make_runtime.py --res results_family results_family_s34",
    "tools/eps_sweep.py --analyse",
    "tools/problem_space.py --res results_family results_family_s34",
    "tools/make_results.py",
    "tools/make_appendix.py",
]


def run(cmd, py=PY):
    print(f"\n=== [{time.strftime('%H:%M:%S')}] {cmd}", flush=True)
    r = subprocess.run(f'"{py}" {cmd}', shell=True, cwd=ROOT)
    if r.returncode:
        sys.exit(f"step failed (exit {r.returncode}): {cmd}")


def zip_paper():
    paper, out = os.path.join(ROOT, "paper"), os.path.join(ROOT, "paper_overleaf.zip")
    keep = ["elsarticle-harv.bst", "elsarticle.cls", "highlights.txt", "main.tex", "refs.bib", "results_text.tex"]
    with zipfile.ZipFile(out + ".tmp", "w", zipfile.ZIP_DEFLATED) as z:
        for f in keep:
            z.write(os.path.join(paper, f), f)
        for sub, ext in (("figures", ".pdf"), ("tables", ".tex")):
            for f in sorted(os.listdir(os.path.join(paper, sub))):
                if f.endswith(ext):
                    z.write(os.path.join(paper, sub, f), f"{sub}/{f}")
    os.replace(out + ".tmp", out)
    print(f"\nwrote {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis-only", action="store_true", help="skip tests and training runs")
    ap.add_argument("--problem-space", action="store_true", help="redo corpus, edits and feature extraction")
    ap.add_argument("--ps-python", default=os.environ.get("MALCERT_PS_PY"), help="python of the malcert-ps env")
    ap.add_argument("--tuning", action="store_true", help="redo grouping selection and the 2i validation grids")
    a = ap.parse_args()
    if not a.analysis_only:
        for t in TESTS:
            run(f"tests/{t}.py")
    if a.problem_space:
        if not a.ps_python:
            sys.exit("--problem-space needs --ps-python (python of the malcert-ps environment, LIEF 0.10.1)")
        for cmd in ("tools/ps_build.py corpus", "tools/ps_build.py corpus --set syswow64 --n 50",
                    "tools/ps_build.py edit", "tools/ps_build.py extract"):
            run(cmd, py=a.ps_python)
        for cmd in ("tools/problem_space.py", "tools/eps_units.py", "tools/extractor_check.py",
                    "tools/edit_families.py", "tools/grouping_footprint.py"):
            run(cmd)
    if a.tuning:
        run("tools/grouping_select.py")
        run("tools/tune_validation.py --split family --out results_tuning")
    if not a.analysis_only:
        for out, args in RUNS:
            run(f"run_all.py {args} --out_dir {out}")
        run("tools/eps_sweep.py --seeds 0,1,2,3,4 --out results_eps_sweep")
    for cmd in ANALYSIS:
        run(cmd)
    zip_paper()


if __name__ == "__main__":
    main()
