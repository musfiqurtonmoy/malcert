# Revision log

One entry per change, tagged with the comment IDs from `REVISION_PLAN.md`
(A1–A6, Am1–Am7: Reviewer A; B1–B8: Reviewer B). Entries tagged `[infra]` answer no comment
directly; they make the later stages possible or reproducible.

Format: **ID** `[comment tags]` what changed, where, and why. Choices that could have been tuned
carry a **Basis:** line saying what they were fixed from.

---

## Stage 0: housekeeping

- **0-1** `[infra]` Git repository created in the project root. The reviewed draft is commit `6b9c09a`,
  tagged `draft-v1`; all revision work is on branch `revision-1`.
  `.gitignore` excludes the BODMAS data files, `__pycache__`, and the problem-space corpus
  (`ps_corpus/`, `ps_tools/`: copies of system binaries and downloaded tools).
  Git was not installed on the PC: a self-contained copy was installed with conda at
  `D:\malcert_envs\git` (git 2.56.1, not on PATH). Commit identity is set for this repository only.
- **0-2** `[infra]` `results_full/` and `results_temporal/` copied to `results_draft_v1/`
  (28 files, hashes identical). These are the numbers the reviewers saw; later stages compare against them.
- **0-3** `[infra]` **Resume support** in `run_all.py`. Results are written after every experiment block
  (atomically: temporary file, then rename). Re-running the same command skips seeds and blocks already in
  `<out_dir>/results.json` and continues with the rest. A resume is refused when the stored configuration
  differs, or when the stored results were produced by different code (compared by a SHA-256 over
  `run_all.py` and `malcert/*.py`), so one results file can never silently mix two versions of the method.
  `--mix_code` overrides this for debugging only.
- **0-4** `[A6, B8]` **Provenance** in every `results.json`: a `provenance` list with one record per run
  (git commit, uncommitted-changes flag, code SHA-256, Python and package versions, platform, device name,
  CUDA version, command line, start time), and per seed `timing` (wall-clock seconds per block) and
  `runs` (which run produced each block). The commit is read from `.git` directly, so it works without git
  on PATH; the uncommitted-changes flag needs git (`GIT_EXE` environment variable or PATH), else it is null.
- **0-5** `[A6, B8]` **Pinned environment**: `environment.yml` (conda-forge + pip, with the PyTorch cu126
  index) and `requirements-lock.txt` (`pip freeze`) for the `malcert` env.
- **0-6** `[infra]` **`--blocks`** option in `run_all.py`: `clean`, `attacks`, `ablation`, `smoothing`,
  `certified`, any subset. The script was restructured into these five blocks without changing what each does.
  - **Change of random stream (deliberate).** In draft v1 all blocks drew from one global random stream, so a
    block's result depended on which blocks ran before it. Each block now reseeds torch at its start
    (`1,000,003 * seed + block index`), and the standard MLP is always trained from the `clean` seed. A block
    therefore gives the same numbers whether it runs alone or with the others. Consequence: numbers of all
    blocks except `clean` shift within run-to-run noise relative to draft v1.
  - `--legacy_rng` keeps the old single stream (all blocks only), to reproduce draft-v1 runs.
  - **Check:** `--preset quick --legacy_rng` (`results_pilot_stage0_legacy/`) reproduces the earlier quick run
    on this PC (`results_pc/`) exactly: 326 of 326 numeric results equal, maximum difference 0. So the
    restructuring changed no behaviour, and runs on this PC are deterministic.
- **0-7** `[A6, B8]` `CLAUDE.md` author line: sole author Md. Musfiqur Rahman.
- **0-8** `[infra]` **Environment repair (not a method change).** `import torch` failed: `torch/lib/cublasLt64_12.dll`
  was 0 bytes. Windows event log: NTFS corruption on C: on 2026-11-09 05:33–05:48, repaired at the next boot.
  All other files of the env were verified against their install checksums (22,853 pip-installed and 5,306
  conda-installed files: no other damage). The DLL was restored from NVIDIA's `nvidia-cublas-cu12` 12.6.4.1
  wheel (PyPI); its SHA-256 equals the one pip recorded when torch was installed. Check 0-6 above confirms
  the repaired install computes identical results.
