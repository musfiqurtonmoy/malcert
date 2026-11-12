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
  `d97a0b523de02f3fe5ea6089d080abacab6ee931` (2022-08-23), installed with `--no-deps` from the commit's
  zip archive (by the author, in a terminal: the assistant's own install was blocked by its permission layer).
  `ember/features.py` and `ember/__init__.py` at that commit were read in full before use; the installed
  `features.py` equals the reviewed copy (line endings aside).
  EMBER's source is AGPL-v3, so it is installed in the env and **not** copied into this repository.
  Pinned in `environment-ps.yml`.
  - **Sanity check (plan 1a):** the 100 originals extracted twice give identical vectors; all 2,418 vectors
    are finite and 2,381-dimensional.
  - **Check against BODMAS:** one corpus file (`cliconfg.dll`) is also in BODMAS (same SHA-256); the vector
    extracted here equals the BODMAS vector in all 2,381 features. One file: supporting evidence that this
    extractor and LIEF version match BODMAS, not proof.

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

### 1d. Measurement
- **1-11** `[A1, B1, B2, A3]` `tools/ps_build.py extract` → `ps_results/features.npz` (2,418 EMBER v2
  vectors: 100 originals, 2,318 edited files). `tools/problem_space.py` → `ps_results/edit_map.csv` (per edit
  and variant), `edit_files.csv` (per file), `unit_evidence.csv` (per feature unit), and
  `paper/tables/tab_edit_map.tex`, `numbers_ps.tex` (macros `\Ps...`). Standardisation: BODMAS training
  statistics, seed 0 (`ps_results/bodmas_train_stats_seed0.npz`). Findings over the 2,018 in-scope files:
  - **Groups.** No edit changes fewer than 2 of the 9 groups: any byte change moves the byte histogram and
    the byte-entropy histogram. Median groups changed: E7 2, E5 3, E1/E2/E6 4, E3 5, E8 6, E4 7 (E9: 8).
    Files needing r ≤ 1: 0%; r ≤ 2: 8.9%; r ≤ 3: 19.9%; r ≤ 4: 64.4%.
  - **Epsilon.** Median ε needed: E7 0.015, E5 0.21, E1 1.7, E8 2.4, E2 9.8, E4 17, E3 22, E6 28.
    Only 14.6% of the files need ε ≤ 0.1 (checksum, DOS-header edits, some 1 KB overlays and timestamps).
  - **Draft-v1 threat set.** 65.6% of the in-scope files lie inside its box and 83.6% inside its group set.
    Reasons for falling outside the box: a feature annotated immutable changed (17.5% of files), an
    "increase-only" feature decreased (11.3%), the vector left the training range (12.4%).
  - E4 through LIEF changes 7 groups, of which 6 come from LIEF rebuilding the import table (control E0
    with import rebuild: 6 groups); a plain LIEF rebuild leaves the vector unchanged in 96 of 100 files.
  - `General.has_relocations` flips in 2 of the 100 files under every append-type edit (E1–E4): an effect
    of how LIEF parses those files, observed, not designed.

### 1e. Threat-model repair (evidence-based part)
- **1-12** `[A1, B1]` **Annotation re-derived from the measurements** and frozen in `malcert/data.py`
  (`MUTABLE_UNITS`, `MONOTONE_UNITS`); `threat_masks()` builds the masks from them.
  Rule, per feature unit, over the in-scope edits E1–E8: *mutable* iff an in-scope edit changed it in at
  least one file or draft v1 already treated it as mutable; *increase-only* iff mutable, a count or size,
  and never decreased. 20 of 81 units change status:
  - lose increase-only (decreased under E8, some also under E3/E7): `Strings.numstrings`, `.printables`,
    `.paths`, `.urls`, `.MZ`, `General.size`;
  - immutable → mutable: `General.has_debug`, `.has_signature` (E8), `.has_relocations` (E1–E4),
    `DataDir.IMPORT_TABLE.address`, `DataDir.IAT.size/.address` (E4),
    `DataDir.CERTIFICATE_TABLE.size/.address`, `DataDir.DEBUG.size/.address` (E8);
  - immutable → increase-only: `Header.sizeof_headers` (E3), `DataDir.IMPORT_TABLE.size` (E4).
  - **Two exceptions, by reasoning, both enlarging the threat set** (`NOT_MONOTONE_BY_REASONING`):
    `Strings.registry` and `Section.n_empty_name` never decreased in the corpus but are not increase-only,
    because E8 (removes bytes) and E6 (renames sections) can lower them by construction.
  - **Kept mutable without observation (conservative):** `Exports.functions`, `General.exports`,
    `Section.n_zero_size`, `Section.n_empty_name`, `Section.entry_characteristics`. No in-scope edit
    changed them; draft v1 treated them as mutable, and removing attacker power needs evidence.
    (`General.exports` and `Section.n_zero_size` therefore also stay increase-only, never having decreased.)
  - Result: **mutable 2,284 → 2,296; increase-only 15 → 9; attackable groups 7 → 9**
    (`Header(static)` through one feature, `DataDir` through 8). `IMMUTABLE_GROUPS` is gone;
    `attackable_groups()` derives the groups from the masks; `run_all.py` uses it for the certificate's
    maximum r and for the group-transplant attack, which may now also transplant Header and DataDir.
  - **Why certificates stay sound:** every change enlarges the threat set (more mutable features, fewer
    one-sided constraints, more attackable groups), and the group certificate's bound
    Δ_r = C(9,k) − C(9−r,k) never assumed any group to be immutable.
  - **Scope of the claim:** the threat set contains every vector the in-scope edits produced on the 100
    measured files (0 of 2,018 outside), plus many they cannot. It says nothing about edits out of scope.
  - **Basis** for every annotation: `ps_results/unit_evidence.csv`; nothing was tuned on test results.
- **1-13** `[B1]` **Annotation tables**: `paper/tables/tab_annotation.tex` (per group, for Section 3) and
  `tab_annotation_full.tex` (per unit: kind, draft and repaired status, rule and observed edits, reference;
  for Appendix C). Not yet referenced from `main.tex`: the manuscript text is Stage 4.

### 1g. Coverage
- **1-14** `[B2]` `paper/tables/tab_coverage.tex`. Status definitions (to go in the caption):
  *covered* = every measured file is inside the threat set and changes at most 4 groups, the largest r a
  vote-counting certificate over 9 groups can reach; *partly covered* = inside the threat set, but files
  change more than 4 groups, so only the box at the listed ε contains them; *out of scope* = outside by design.
  Covered: overlay append, string padding, timestamp edit, section renaming, checksum and DOS-header edits.
  **Partly covered, against the plan's expectation: section injection (5–6 groups), import addition (7),
  signature and debug stripping (6).** Out of scope: UPX packing (measured: 8–9 groups, every file changes
  features annotated immutable), repacking, obfuscation and metamorphism, dropper wrapping (not measured).
  "Covered" means a certificate can apply, not that samples are certified at that r: in draft v1 the
  certified detection at r = 4 was 0.

### Pilot
- **1-15** `[A1, B1]` Quick pilot with the repaired threat model: `results_pilot_stage1/` (commit `f5e1049`,
  no uncommitted changes, 1 seed, 7.2 min). **All 8 `violations` are 0.** Compared with
  `results_pilot_stage0/` (same code path and seeding, draft-v1 threat model), so differences are the repair:
  - unchanged: clean metrics of every model; group-ablation certified detection for all k and r (the
    certificate never used the annotation), e.g. k=1: 90.8 / 78.7 / 64.0 / 0.0 % at r = 1..4;
  - group-transplant attack, now allowed to transplant Header and DataDir: empirical detection of the k=3
    detector at r=2 falls from 11.3% to 4.0%; other cells move by at most 0.3 points;
  - constrained PGD is stronger (larger box): detection of the standard MLP at ε=0.05 falls 71.9 → 69.2%,
    of PGD-AT at ε=0.2 67.5 → 64.7%;
  - certified detection at the training budget ε=0.05 barely moves (CROWN-IBP 97.3 → 97.3%, IBP 96.8 → 96.5%),
    but at ε=0.1 it falls: CROWN-IBP 49.3 → 44.9%, IBP 31.1 → 26.5%, asymmetric CROWN-IBP 31.4 → 19.8%.
  One seed, quick budgets: directions are indicative only; the full runs are Stage 3.
- **Open:** plan section **1h** (announced by the author) is not in the `REVISION_PLAN.md` on disk and was
  therefore not done.

### Tests
- **1-10** `[A1, B1]` `tests/test_threat_model.py` (8 tests): units tile the vector and respect groups;
  annotation well-formed; natural bounds hold on BODMAS; box not clipped at the training maximum; attack
  projection and certificate box describe the same set; every in-scope edited file is inside the threat set
  (groups, and box at the ε it needs); frozen annotation equals the evidence rule; block bookkeeping of
  `run_all.py`.
