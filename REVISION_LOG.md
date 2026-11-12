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
- **0-9** `[infra]` **Resume checked end to end** (`results_pilot_stage0/`, Stage 0 code, quick preset, new
  per-block seeding): `--blocks clean` alone; then all blocks, which ran only the four missing ones; then the
  same command again, which skipped the seed; then `--preset full` into the same folder, which was refused
  (different configuration). This folder is also the like-for-like baseline for the Stage 1 pilot: same code
  path and seeding, draft-v1 threat model.
- **0-10** `[infra]` `git_commit()` in `run_all.py` now also resolves the commit inside a linked git worktree
  (the baseline run above logged "commit none" because `.git` is a pointer file there).

---

## Stage 1: problem-space check and threat-model repair

### 1a. Environment
- **1-1** `[A1, B1]` Conda env **`malcert-ps`** at `D:\malcert_envs\malcert-ps` (registered in conda's
  `envs_dirs`, so `conda activate malcert-ps` works): **Python 3.7.12, lief 0.10.1**, numpy 1.21.6,
  scikit-learn 1.0.2, pandas 1.3.5, lightgbm 3.3.5.
  - **Deviation from the plan (Python 3.7, not 3.8).** LIEF 0.10.1 was published for Python 3.5–3.7 only
    (PyPI and the LIEF GitHub release were both checked). The plan's fallback was "the closest LIEF version
    that installs"; instead the LIEF version was kept exact and Python lowered, because the EMBER README
    names LIEF 0.10.1 as giving consistent version-2 features on Windows, and the Python version does not
    enter the feature computation. **Basis:** EMBER README, "Notes on LIEF versions".
  - numpy < 1.24 and scikit-learn 1.0.2 are needed by the EMBER extractor as published (`np.int`;
    `FeatureHasher` on a bare string).
- **1-2** `[A1, B1]` **EMBER feature extractor**: `github.com/elastic/ember`, commit
  `d97a0b523de02f3fe5ea6089d080abacab6ee931` (2022-08-23), installed with `--no-deps`.
  `ember/features.py` at that commit was read in full before use (feature extraction only).
  EMBER's source is AGPL-v3, so it is installed in the env and **not** copied into this repository.

### 1b. Corpus
- **1-3** `[A1, B1, B2]` `tools/ps_build.py corpus`: **100 benign PE files** (50 `.exe`, 50 `.dll`) copied
  from `C:\Windows\System32` to `ps_corpus/orig/` (not versioned). Selection: files of 16 KB–4 MB, shuffled
  with seed 0, first 50 of each kind that LIEF parses; no candidate had to be skipped.
  Sizes 17 KB–3.4 MB (median 140 KB, total 40.5 MB). 27 carry an embedded signature, 99 a debug directory.
  Manifest with SHA-256: `ps_results/corpus_manifest.csv`.
  **Limitations to state in the paper:** all files are benign, 64-bit (AMD64) Microsoft binaries.
  **Basis** for the size window and seed: fixed before any feature was extracted.

### 1c. Edits
- **1-4** `[A1, B1, B2]` `tools/ps_build.py edit`: every edit writes a new file under
  `ps_corpus/edited/<edit>/<variant>/`; originals are never changed; **no edited file is ever executed**
  (the only check is that LIEF re-parses it). Outcome per file: `ps_results/edits_manifest.csv`.

  | Edit | Variants | Files written (of 100) |
  |---|---|---|
  | E1 overlay append | 1 KB, 64 KB, 1 MB × random / benign bytes | 100 each |
  | E2 string padding | 50, 500 strings (URLs, paths, registry keys) | 100 each |
  | E3 section add (LIEF) | 4 KB, 64 KB × random / benign | 100 each |
  | E4 import add (LIEF) | 1, 10 `kernel32.dll` functions | 96 each (LIEF `not_found` on 4 files) |
  | E5 COFF timestamp | random date 2000–2025 | 100 |
  | E6 section rename | random 8-character names | 100 |
  | E7 header fields | checksum; DOS header 0x02–0x3B; DOS stub | 100 each |
  | E8 strip | embedded signature; debug directory | 27; 99 (where present) |
  | E9 UPX 5.3.0 | default; `--force` | 3; 97 |
  | E0 LIEF rebuild (control) | plain; with import rebuild | 100 each |

  - **Added to the plan:** `E0`, a control (LIEF rebuilds the file without any edit). LIEF's builder rewrites
    the whole file, so E0 separates what E3/E4 change by rebuilding from what the edit itself changes.
  - **Added to the plan:** E7 variant `dos_stub`, and E9 variant `--force`. UPX with default settings refuses
    97 of the 100 files (87 Control Flow Guard, 8 forced integrity check, 2 unsupported subsystem), which is a
    property of modern Microsoft binaries; `--force` is measured as a second, separately labelled variant.
  - UPX: official release v5.3.0 from `github.com/upx/upx`, zip SHA-256 equal to the published digest.
- **1-5** `[A1]` **E8 is in scope** (the plan left this to the evidence). Basis: all stripped files re-parse;
  Anderson et al. (2018, Sec. 3.4) list "removing signer information" and "manipulating debug info" among
  their functionality-preserving actions. Recorded in `EDIT_SCOPE` in `malcert/data.py`.
- **1-6** `[Am7]` `paper/refs.bib`: added `anderson2018learning` (Anderson, Kharkar, Filar, Evans, Roth,
  arXiv:1801.08917, 2018). Title, authors and the action list (Sec. 3.4) were checked against arXiv;
  **still to do before submission: the Google Scholar check** that `CLAUDE.md` requires for every reference.

### 1e. Threat-model repair (part that needs no measurement)
- **1-7** `[A1, B1]` **Training-range clip removed** from `input_box` (`malcert/models.py`) and
  `Constraints.project` (`malcert/attacks.py`). Draft v1 intersected the box with
  [training minimum, training maximum] per feature. That is unsound: an edited file can exceed the largest
  value in the training set, so points an attacker can reach were excluded from the certified region.
  The box now keeps only **natural bounds** (`natural_bounds()` in `malcert/data.py`), which hold for every
  PE file because of how the extractor computes the feature:
  normalised histograms and 0/1 flags in [0, 1]; counts, sizes and other non-negative values ≥ 0;
  hashed features unbounded.
  - **Why this keeps certificates sound:** a natural bound is satisfied by every feature vector any file can
    have, so intersecting the box with it removes no reachable point; everything else only enlarges the box.
  - **Verified from the data:** all 134,435 BODMAS rows satisfy the bounds (histograms sum to 1 with bins
    in [0, 1]; no negative count, size, flag or version field; every hashed block has negative entries).
  - `Preprocessor.bounds()` maps the bounds to standardised space; `Preprocessor.zmin/zmax` are gone.
- **1-8** `[B1]` **Feature units** (`FEATURE_UNITS` in `malcert/data.py`): the 2,381 features as 81 named
  pieces with a kind (hist / count / flag / value / hashed), read from `ember/features.py`. The annotation,
  the natural bounds and the annotation tables are all defined per unit.
  The draft annotation is kept as `threat_masks_draft_v1()` for comparison only (2,284 mutable, 15 monotone).

### 1f. Epsilon in real units
- **1-9** `[Am2]` `tools/eps_units.py` → `ps_results/eps_units.csv`, `paper/tables/tab_eps_units.tex`,
  `paper/tables/numbers_eps.tex` (macros `\Eu...`). For the median test malware (seed 0), it inverts the
  standardisation: the raw increase that ε = 0.01, 0.05, 0.1 allows on file size, strings, imports, sections
  and one byte-histogram bin, and the ε one more unit needs. When the edit map exists, the table also lists
  the ε each real edit needed.

### Tests
- **1-10** `[A1, B1]` `tests/test_threat_model.py` (8 tests): units tile the vector and respect groups;
  annotation well-formed; natural bounds hold on BODMAS; box not clipped at the training maximum; attack
  projection and certificate box describe the same set; every in-scope edited file is inside the threat set
  (groups, and box at the ε it needs); frozen annotation equals the evidence rule; block bookkeeping of
  `run_all.py`.
