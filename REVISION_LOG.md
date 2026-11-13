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
  - LIEF rebuild controls: a plain rebuild (E0, control for E3) leaves the vector unchanged in 96 of 100
    files; a rebuild with the import table (E0, control for E4) changes 6 groups by itself. See 1-16 for the
    separation of the edit's own footprint.
  - `General.has_relocations` flips in 2 of the 100 files under every append-type edit (E1–E4); see 1-17.

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
  Section 1h (below) was done after this pilot; it changed only analysis tools, not `run_all.py` or
  `malcert/`, so the pilot is still the result of the current method code.

### 1h. Coverage of the L-infinity certificate, and loose ends
(The plan was updated on 2026-11-13 with this section and a rewritten 2b; 2b belongs to Stage 2.)
- **1-16** `[A1, B2]` **Edit footprint separated from rebuild footprint** (`tools/problem_space.py`): for the
  LIEF edits the edited file is also compared with the same file rebuilt by LIEF without the edit
  (E0 `plain` for E3, E0 `imports` for E4). New columns `groups_edit_only_*`, `groups_rebuild_median`,
  `own_share_<group>` in `edit_map.csv`; a sub-row "of which the edit itself" and one row per control in
  `tab_edit_map.tex`; macros `\PsEthreeOwnGroups*`, `\PsEfourOwnGroups*`, `\Ps*RebuildGroupsMed`.
  - E3: the edit itself changes 5 groups in every file; the sixth group (Header, 3% of files) is the rebuild's.
  - E4: the import rebuild alone changes 6 groups, **and the edit itself still changes 7** relative to the
    rebuilt file. The rebuild therefore does not inflate E4's footprint. (An earlier wording of entry 1-11,
    "6 of the 7 groups come from the rebuild", was wrong and has been replaced.)
- **1-17** `[B1]` **`General.has_relocations` under append-only edits: a LIEF artefact, documented.**
  In `dsregcmd.exe` and `wsmprovhost.exe` the relocation directory is present and well formed (7 and 3
  blocks, which LIEF parses in the original and in every edited copy), and the table ends at the last byte
  of the file (resp. 4 bytes before it). LIEF 0.10.1 then reports `has_relocations = False`; once any bytes
  follow the table it reports `True`; in-place edits leave it `False`. These are the only 2 of the 97 corpus
  files with a relocation directory for which LIEF reports none. The files' relocations do not change, but
  the feature the detector sees does, so it stays **mutable**. Macro `\PsNRelocArtefact`.
- **1-18** `[A1, Am2]` **Coverage of the L-infinity certificate as a function of ε.**
  `ps_results/eps_coverage.csv` (share of in-scope edited files with ε needed ≤ ε, overall and per edit;
  macros `\PsEpsLeTrainPct`, `\PsEpsLeTenthPct`, `\PsEpsLeOnePct`, `\PsEpsLeTenPct`), and
  `tools/eps_coverage.py --res <results>` → `paper/figures/fig_eps_coverage.*`,
  `paper/tables/tab_eps_coverage.tex`, `ps_results/eps_coverage_vs_certified.csv`: that share next to the
  certified detection of the standard, IBP and CROWN-IBP networks at the same ε.
  - Finding: 12.0% of the measured edits fit at ε ≤ 0.05 and 14.6% at ε ≤ 0.1 (checksum and DOS-header
    edits, some 1 KB appends and timestamp edits); 30.8% at ε ≤ 1; 59.5% at ε ≤ 10. String padding needs
    about 8–15, section and import addition about 17–22, section renaming about 28.
  - **To state plainly in the paper (Stage 4):** the L-infinity certificate covers only header-level and
    very small edits; the emphasis moves to the group certificate.
  - **The certified-detection values in the figure and table are from the quick pilot**
    (`results_pilot_stage1`, 1 seed). Rerun the script on the final results before they enter the paper.
- **1-19** `[B1]` Reasoned annotation decisions are labelled **"conservative, not observed"** in
  `unit_evidence.csv` and `tab_annotation_full.tex`: the two units not treated as increase-only
  (`Strings.registry`, `Section.n_empty_name`) and the five kept mutable without an observed change.

### 1i. Addendum (commit `d5bde79`)
- **1-20** `[A1, B1, B3]` **PE32 files.** 50 benign PE32 (I386) files from `C:\Windows\SysWOW64` (25 exe,
  25 dll, 17 KB–1.7 MB), copied as `w32__<name>` (`ps_build.py corpus --set syswow64`); every edit rerun
  on them, donors drawn within the set. Edit map per architecture: `edit_map.csv` (`arch` column),
  `paper/tables/tab_edit_map_arch.tex`. Groups touched are the same for PE32 and PE32+ (medians equal for
  every edit; E3 max 5 vs 6); ε needed differs little (E1 2.3 vs 1.7, E2 11.8 vs 9.8, E6 19.5 vs 27.9).
  E4 and the E0 import rebuild produce unparsable files for 28 of 50 PE32 files (LIEF 0.10.1 builder),
  so E4 rests on 22 PE32 files.
  **Annotation difference:** on PE32 files alone the rule would give 4 different statuses
  (`Strings.paths`, `DataDir.IAT.size` increase-only instead of mutable; `General.has_relocations`,
  `Header.sizeof_headers` immutable instead of mutable/increase-only). The frozen annotation is the union
  over both architectures, i.e. always the larger threat set, so no change is needed.
- **1-21** `[A1, B1]` **Edit E10** (`ps_build.py`, in scope in `EDIT_SCOPE`, "plausibly
  functionality-preserving, not verified by execution"): each field on its own: linker major/minor and image
  major/minor set to another random value; OS and subsystem major lowered (floor 4) and minor lowered;
  DYNAMIC_BASE and NX_COMPAT cleared. E10 changes 2–3 groups (Header plus the byte histograms) and needs
  ε 0.9–20. OS-minor lowering never applied (every corpus file has OS minor version 0); subsystem-minor
  applied to 6 files only.
  **Annotation changes (8 units, immutable → mutable, all through E10 only):** `Header.dll_characteristics`
  (10 hashed features), `.major_image_version`, `.minor_image_version`, `.major_linker_version`,
  `.minor_linker_version`, `.major_os_version`, `.major_subsystem_version`, `.minor_subsystem_version`.
  `Header.minor_os_version`, machine, magic, subsystem, characteristics and sizeof_code stay immutable.
  **Final counts: mutable 2,313 (draft 2,284), increase-only 9 (draft 15), attackable groups 9 of 9.**
  All 4,169 in-scope edited files (2,819 PE32+, 1,350 PE32) lie inside the repaired threat set.
- **1-22** `[A1, B1]` **Extractor compatibility** (`tools/extractor_check.py` → `ps_results/extractor_check.json`,
  `extractor_units.csv`, `paper/tables/numbers_xc.tex`, macros `\Xc...`):
  - exact SHA-256 matches with BODMAS: 1 of 150 (`cliconfg.dll`, BODMAS label benign), vector identical
    in all 2,381 features; no PE32 file is in BODMAS;
  - a LightGBM trained on BODMAS (seed-0 split, run_all.py settings; test accuracy 99.53%, FPR 0.35%)
    classifies **150 of 150** corpus originals as benign (median score 0.0000);
  - 3 files have a value outside the range of all BODMAS rows (1 in ByteHistogram, 2 in Imports.libraries);
    0.80% of feature entries lie outside the BODMAS-benign 1–99% band (2% for BODMAS benign by construction).
  Conclusion: no sign that the vectors extracted here are off-distribution for BODMAS.
- **1-23** `[B2]` **Coverage table: three levels** (`tab_coverage.tex`, `ps_results/coverage.csv`):
  (a) inside the threat set and certified, with the measured certified detection at the r the edit needs
  (the largest r observed for it); (b) inside but not certifiable; (c) out of scope.
  Already (b) under the 9 EMBER groups: E3 (r = 6), E4 (7), E8 (6). E1, E2, E5, E6, E7, E10 are filled in
  after Stage 2b (`problem_space.py --res <results>`); until then they read "to be measured".
- **1-24** `[infra]` **Memory** (`tools/mem_dry_run.py` → `checks/memory_dry_run.json`). New
  `load_full()` (all 134,435 rows, loaded once, float32) and `Preprocessor.fit_transform_inplace()`
  (statistics in float64, standardised in place, row chunks). Peak RAM: 30K-subset path 1.04 GB (commit
  2.15 GB); full data, lean path **1.46 GB** (commit 1.83 GB; one copy of X = 1.19 GiB). The naive path on the
  full data is estimated at about 7.2 GB and was not run. Heavy jobs one at a time.
  Test: the in-place path is checked against a float64 reference and is at least as accurate as
  `fit`/`transform` (which accumulates in float32: up to 2e-4 relative error in sd on low-spread features).
- **1-25** `[A6, B8]` **Backup.** Remote not yet set: creating a private GitHub repository needs the
  author's login. Steps are in `RUN_NEXT.md` (repository is 12.8 MB; `data/`, `ps_corpus/`, `ps_tools/`
  are not tracked).

- **1-26** `[A1, B1]` **Pilot** `results_pilot_stage1i/` (commit `d5bde79`, clean, quick preset, 1 seed):
  all 8 `violations` 0; data records 2,313 mutable, 9 increase-only, 9 attackable groups. Against
  `results_pilot_stage1/`: clean metrics and group-ablation certificates identical (k=1: 90.8 / 78.7 / 64.0%
  at r = 1..3); the 17 newly mutable header features enlarge the L∞ box, so certified detection at ε = 0.1
  falls a little more (CROWN-IBP 44.9 → 41.5%, IBP 26.5 → 23.5%, asymmetric 19.8 → 18.7%) and constrained
  PGD against PGD-AT at ε = 0.2 is stronger (64.7 → 59.8% detected). At ε = 0.05 CROWN-IBP is 97.1%
  (draft v1, full: 97.9%).

- **1-27** `[A1, B1]` **Decisions on 1i (author, 2026-11-13).** E10 stays in scope. The reported ε coverage is
  over all in-scope edits including E10: **8.1% of measured edits fit at ε ≤ 0.05** (`\PsEpsLeTrainPct`);
  the 12.0% of 1h was E1–E8 on PE32+ only. `Header.minor_os_version` is mutable, "conservative, not observed"
  (`MUTABLE_BY_REASONING` in `malcert/data.py`, honoured by the evidence rule). Mutable features 2,313 → **2,314**;
  increase-only 9; attackable groups 9 of 9. Unit tests pass (10).

---

## Stage 2: method changes

### 2a. Exact certificate and ceiling
- **2-1** `[A3]` `malcert/certify.py`: `ablation_view_votes` (per-view votes), `ablation_certify_exact`
  (worst case over every set A of r **attackable** groups: certified iff correct untouched votes > wrong
  untouched votes + touched views; strict, ties not certified), `ceiling_r(G, k)` (largest r with
  2·C(G−r,k) > C(G,k)). Ceiling for G = 9 reproduces the plan's table (k = 1..5: 4, 2, 1, 1, 0).
  Keep sizes: k ≥ 5 certifies nothing; k = 4 reaches no larger r than k = 3; no k = 4 experiment (plan).

### 2b. Edit-aligned grouping
- **2-2** `[A1, A3, B2, B5]` **Candidates** (`malcert/partitions.py`), built from `ps_results/unit_evidence.csv`
  co-change data only. Blocks: CONTENT (byte and byte-entropy histograms, all strings, size,
  has_relocations, timestamp: changed by every in-scope edit), HDRMUT (E10 fields), SIGDBG (E8 flags and
  data-directory entries), SECTION (sizeof_headers, vsize, all section features), IMPORTS (import/export
  counts and hashes, import-table and IAT entries), IMMHDR and IMMDD (features no in-scope edit changes).
  `aligned4` = {CONTENT+HDRMUT+SIGDBG, SECTION, IMPORTS, IMMHDR+IMMDD} (G 4, 3 attackable);
  `aligned5` = aligned4 with IMMHDR and IMMDD separate (G 5, 3 attackable);
  `aligned7` = {CONTENT, HDRMUT, SIGDBG, SECTION, IMPORTS, IMMHDR, IMMDD} (G 7, 5 attackable);
  `ember` = the 9 EMBER blocks (all attackable). r needed per edit (max over files, `tools/grouping_footprint.py`
  → `ps_results/grouping_footprint.csv`): ember 3–7; aligned4/5: E1, E2, E5, E7, E10 = 1, E3, E6, E8 = 2, E4 = 3;
  aligned7: same but E8 = 3, E10 = 2.
- **2-3** `[A3, B5]` **Selection rule, fixed before any evaluation** (validation split only; test not used):
  - Configurations: ember k = 1, 2, 3; aligned4 k = 1; aligned5 k = 1, 2; aligned7 k = 1, 2, 3
    (k values whose ceiling is ≥ 1).
  - Data and training: 30K subset, random split seed 0, quick-preset budgets (15 epochs, MLP 512-256),
    torch seed fixed per configuration. Evaluated on the 3,001-sample validation split.
  - For each configuration and in-scope edit type e (E1–E8, E10): r_e = max groups touched over the
    measured files; c_e = share of validation malware certified by the **exact** certificate at r_e
    (0 if r_e exceeds the ceiling).
  - Score = mean of c_e over the 9 edit types. Eligible: validation clean accuracy at least the best
    validation clean accuracy among all configurations minus 1.0 point.
  - Select the eligible configuration with the highest score; within 0.5 points, prefer fewer views,
    then higher clean accuracy.

- **2-4** `[A3, B5]` **Validation results** (`tools/grouping_select.py` → `results_grouping_val/`; 3,001 validation
  samples, 1,278 malware; test split not used). Validation clean accuracy: ember k=1/2/3 97.23 / 98.13 / 98.73%;
  aligned4 k=1 97.83%; aligned5 k=1/2 96.73 / 98.97%; aligned7 k=1/2/3 95.37 / 98.00 / 98.90%.
  Score (mean certified detection over the 9 edit types): ember 20.9 / 0 / 0; aligned4 45.7; aligned5 70.8 / 45.8;
  aligned7 81.2 / 40.2 / 39.6. Eligibility cut 98.97 − 1.0 = 97.97% excludes every k = 1 configuration.
  **Selected by the rule: aligned5, k = 2** (10 views, ceiling r = 1). Certified at r = 1: E1, E2, E5, E7, E10,
  each 82.5% of validation malware. Not certifiable (r needed 2 > ceiling 1): E3, E6, E8; E4 (r = 3).
  The rule's accuracy cut, not the score, decided: aligned7 k = 1 certifies all 9 types (61–90%) but has
  3.6 points lower validation accuracy (FPR 3.4%). Flagged to the author.
  Exact vs 2·Δ bound: largest gain 0.08 points (ember k = 3, aligned7 k = 2), as the plan's pre-check expected.
  `grouping` config field added (default still `ember` until the author approves the selection);
  `run_all.py` ablation block now records the exact certificate, the ceiling, per-view vote rates and uses
  the exact certificate for the violation check. Unit tests: 15 pass.

- **2-5** `[A3, B5]` **Decision (author, 2026-11-13), declared before any test evaluation**
  (REVISION_PLAN "2b result and decision"): main configuration **aligned5, k = 2** (the rule's choice);
  second operating point **aligned7, k = 1**, reported as the coverage/accuracy trade-off, not as the
  recommended detector. Both are evaluated in Stage 3 on all splits and seeds. LightGBM per-view (2c) uses
  the main configuration only. EMBER groups are the negative baseline. No test-split result of any edit-aligned
  grouping exists at the time of this entry.

### 2c–2f (commits `1c58f87`, `097e62a`)
- **2-6** `[A3, B5]` `config.ablation_configs` = main (aligned5, k=2), second (aligned7, k=1), ember (EMBER groups,
  k=1, negative baseline); `run_all.py` evaluates all three, records exact certificate, bound, ceiling,
  certified detection per in-scope edit type at the r it needs (`cert_by_edit`), per-view vote rates.
  `--eval_split val` added: pilots before Stage 3 evaluate on the validation split, never on test.
- **2-7** `[A2]` **2c LightGBM per view** (main configuration only, 200 trees per view, fixed): 10 models.
- **2-8** `[A2]` **2d** certified training keeps four models: standard, PGD-AT, CROWN-IBP trained on the constrained
  box, CROWN-IBP trained on the unconstrained L∞ ball (`crownibp_unc`); each certified on both boxes (2 × 2).
  Plain IBP and asymmetric CROWN-IBP removed.
- **2-9** `[A2]` **2e** monotonic LightGBM (`monotone_constraints=+1` on the 9 increase-only features);
  Giri et al. re-implementation (`RandomAblationMLP`: each EMBER group dropped with p = 0.2, Gaussian noise
  σ = 0.3 on all features in training and in CERTIFY, L2 radius; labelled re-implementation; deviations: MLP base
  instead of LightGBM, EMBER groups instead of their ~50-feature groups, noise on every sample, σ in standardised
  units). Uniform group-transplant attack on all 13 models, in the main partition's groups, same donors.
- **2-10** `[A4, B5]` **2f** cost records per model (training s, certification ms/sample, forward passes/sample)
  → `tools/make_runtime.py` → `paper/tables/tab_runtime.tex`.
- **2-11** `[infra]` **Bug found and fixed in the pilot:** the group attack scored LightGBM models on vectors
  round-tripped through the standardisation; an exact 0 came back as ~1e-8 and flipped LightGBM splits
  (LightGBM "detected" only 74% at r = 0; 302 false violations for per-view LightGBM). The attack now runs in
  raw space for raw-feature models. The buggy pilot is kept as `results_pilot_stage2_rawbug/`.
- **2-12** `[A2, A3, A4, B5]` **Stage 2 pilot** `results_pilot_stage2/` (commit `097e62a`, quick, 1 seed, **validation
  split**): all 8 violations 0. Clean accuracy: LightGBM 99.3, monotonic LightGBM 99.4, MLP 99.2, PGD-AT 99.4;
  main 99.0 (certified 83.2% at r = 1); second 95.2 (90.5 / 84.4 / 61.6% at r = 1, 2, 3); ember k=1 97.4 (65.4% at
  r = 3, 0% at r = 4); LightGBM-per-view main 99.4 (certified **96.6%** at r = 1). Certified training at
  ε = 0.05 / 0.1, constrained box: CROWN-IBP constrained-trained 97.2 / 40.5, unconstrained-trained 97.5 / 53.6
  (**negative for the constrained-training claim**); certified on the unconstrained ball: 96.5 / 19.8 vs 97.2 / 28.9.
  Giri re-impl.: accuracy 99.0, abstain 0.2%. Group attack (r = 1): every non-ablation model ≤ 10.3%
  detected (LightGBM and monotonic LightGBM 0%); ablation main 90.3%, LightGBM views 98.3%.
- **2-13** `[A4, B5]` **Stage 3 estimate** (from the pilot, scaled to full-preset budgets; to be re-measured on the
  first Stage 3 seed): about 16 min per seed without smoothing, plus about 14 min per seed for smoothing on every
  test point (2 σ + Giri, n = 10,000). Run set: 5 family + 3 random seeds without smoothing (2.1 h), smoothing on
  3 seeds (0.7 h), temporal 2 cut-offs × 3 seeds, clean/ablation/certified blocks (1.4 h), full-data check (0.8 h):
  **about 5 h total**.

### 2g–2i decisions (author, 2026-11-13; logged before any run)
- **2-14** `[A2, A3, B5]` **2g.** C3 stays, redefined as edit-aware certified training (2h); box-constrained
  CROWN-IBP is kept as an ablation, compared with uniform-ball training under the original rule (paired 95%
  interval at ε = 0.05, family split), reported whatever the outcome. Certification on the constrained box is kept.
  The 8.1% L∞ coverage at ε = 0.05 is stated next to every certified-training number. Headline group-certified
  detector: per-view LightGBM, aligned5 k = 2; per-view LightGBM is added for aligned7 k = 1 (7 models, 200 trees),
  declared before any test evaluation. Giri re-implementation unchanged; deviations go to Appendix B.
- **2-15** `[A2, A3]` **Pre-registered C3 rule (2h.8):** C3 is claimed if edit-aware CROWN-IBP > uniform-ball
  CROWN-IBP in certified detection over T_f(1), averaged over the four families, with a paired 95% interval
  above zero on the family split (5 seeds). Otherwise the result is reported as it is.
- **2-16** `[A1, A3]` **2h details fixed here (not specified in the plan):** halves = random 50/50 split of the
  150 originals, stratified by architecture, seed 0; all edits of an original follow it. Support S_f = features
  changed in ≥ 1% of the family's fit-half edited files. lo/hi = 2.5th / 97.5th percentile of the change over the
  fit-half files where the feature changed, widened to include 0 (so lo = 0 when only increases were seen).
  Changes are stored in signed-log units, Δ = slog(x') − slog(x), and divided by each run's standardisation sd
  (Δz = Δ / sd exactly; mu cancels), so the sets and their coverage do not depend on the seed's statistics.
- **2-17** `[A2, A5]` **2i grids and selection metrics** (validation split only; seed 0):
  - MLP: lr {1e-3, 3e-4} × epochs {30, 60}; metric validation accuracy. The chosen lr and epochs become
    `cfg.lr` / `cfg.epochs`, i.e. the base settings of every MLP-based model not tuned separately.
  - Per-view LightGBM, aligned5 k = 2 and aligned7 k = 1: n_estimators {200, 500} × num_leaves {31, 64}.
  - aligned7 k = 1 MLP views: epochs {30, 60, 90}.
  - Uniform-ball CROWN-IBP: ε_train {0.05, 0.1}; box-constrained CROWN-IBP: same grid.
  - Edit-aware CROWN-IBP: t_train {0.5, 1} × aggregation {mean, max}.
  - Metric for certified detectors: maximise certified detection on validation malware subject to validation
    FPR ≤ 1% (else the lowest-FPR setting). For group-certified detectors, certified detection = mean over the
    9 in-scope edit types at the r each needs (as in 2-3). For all three CROWN-IBP variants, certified detection =
    mean over the four families of certified detection over T_f(1), the set the C3 rule uses.
  - **Split:** the plan says family split, which is built in Stage 3b. The script takes `--split`; which split
    to use for the grid run is put to the author (`RUN_NEXT.md`).

### 2h–2i implementation
- **2-18** `[A1, A2, A3]` **2h edit families** (`tools/edit_families.py` → `ps_results/corpus_halves.csv`,
  `edit_families.npz`, `family_coverage.csv`, `paper/tables/numbers_fam.tex`). Halves: 75 fit / 75 eval
  originals. Supports: F_content 625, F_section 784, F_import 654, F_strip 617 features. Eval-half coverage of
  T_f(t) at t = 0.25 / 0.5 / 1 / 2: content 15.5 / 25.3 / 67.3 / 78.8%; section 0 / 0 / 21.6 / 51.2%;
  import 0 / 0 / 0 / 0.9%; strip 0 / 0 / 16.9 / 36.0%. Low values for section, import and strip: a file counts
  only if every one of its several hundred changed features lies inside its 95% interval; hashed import features
  change sparsely, so an import edit nearly always hits a bucket outside the interval or the support.
- **2-19** `[A2, A3]` `malcert/models.py`: `family_box` (T_f(t), natural bounds kept), `load_families`;
  `malcert/train.py`: edit-aware CROWN-IBP (robust loss over the four family boxes, mean or max, t ramped to
  t_train); `run_all.py` certified block: models standard, PGD-AT, CROWN-IBP box, uniform-ball (ε =
  `unc_train_eps`), edit-aware; every model certified on T_f(t) per family and for all four families
  (`family_cert`), and the corpus soundness check `corpus_violations` (must be 0). Per-view LightGBM now runs for
  main and second (`lgbm_view_params`).
- **2-20** `[A1]` `tests/test_families.py`: box shape; every eval-half edited vector counted inside T_f(t) lies in
  `family_box`, and for a network with shrunk weights on the support features (so that certificates are not
  vacuous) no certified original is flipped by its real edit: 3,130 cases inside, 3,129 certified, 0 flipped.
  All 17 unit tests pass.
- **2-21** `[A2, A5]` **2i** `tools/tune_validation.py` (grids and metrics of 2-17; validation only). Smoke test
  (`results_tuning_smoke/`, 1 epoch, first grid point each): all 7 models run. Edit-aware CROWN-IBP 2.7 s per epoch
  vs 1.0 s for box CROWN-IBP (incl. validation certification; 4 family boxes per batch). Full grid command in
  `RUN_NEXT.md`; split choice (random now, or family after 3b) is with the author.

### 2h-revision and split decision (author, 2026-11-13; logged before any run)
- **2-22** `[A5, B4]` 2i is **not** tuned on the random split (its validation set shares families with training).
  The family-disjoint split function and its unit test (from 3b, nothing else of 3b) are built now; the 2i grid
  uses the validation part of the family split, seed 0. Log 2-16 and 2-17 approved except the interval rule.
- **2-23** `[A1, A3]` **Interval rule replaced (plan "2h-revision")**, using only extractor structure and the fit half:
  - Name-hashed blocks are structural: `Imports.libraries`, `Imports.functions`, `Exports.functions` and the five
    hashed `Section.*` blocks (sizes, entropy, vsizes, entry_name, entry_characteristics: all hashed by section
    name). For a family that changes any feature of such a block in the fit half, the whole block is in the support
    and every bucket may change by ±m_f, m_f = the largest per-bucket |change| in that block in the family's fit half.
    Hashed header blocks (machine, characteristics, subsystem, dll_characteristics, magic) hash a fixed vocabulary,
    not names, so they follow rule 2. (Interpretation of "section-name blocks"; flagged to the author.)
  - All other features: [min, max] of the change over fit-half files where it changed, widened to include 0.
  - Support threshold (≥ 1% of fit-half files) unchanged for non-hashed features; t grid unchanged.

- **2-24** `[A5, B4]` **Family-disjoint split** `family_split()` in `malcert/data.py` (`--split family`): malware
  families visited in seeded random order, each to the part furthest below its 70/10/20 malware target (relative);
  benign split at random 70/10/20. `tests/test_split.py` (2 tests: disjoint families, every sample once, both
  classes per part, shares within 3 points, deterministic, seeds differ). Seed 0: train 20,782 (8,724 malware,
  68.3%; 259 families), val 3,077 (1,354, 10.6%; 37 families), test 6,141 (2,695, 21.1%; 57 families).
  Malware mix: train trojan 50.7 / worm 31.9 / backdoor 11.9%; val 62.7 / 4.9 / 28.8%; test 52.1 / 32.4 / 7.6%.
  The validation part has few families, so its mix differs from train and test.
- **2-25** `[A1, A3]` **2h-revision implemented** (`tools/edit_families.py`). Supports: content 625, section 820,
  import 2,053, strip 665 (before: 625 / 784 / 654 / 617). Eval-half coverage at t = 0.25 / 0.5 / 1 / 2:
  content 24.7 / 39.9 / 84.0 / 93.2%; section 0 / 8.3 / 65.1 / 81.9%; import 0 / 0 / 7.0 / 28.1%;
  strip 0 / 0 / 37.1 / 52.8%. Before (95% intervals, `family_coverage_v1.csv`): content 15.5 / 25.3 / 67.3 / 78.8;
  section 0 / 0 / 21.6 / 51.2; import 0 / 0 / 0 / 0.9; strip 0 / 0 / 16.9 / 36.0 (computed with the loose
  tolerance below, so slightly overstated).
- **2-26** `[A1]` **Bug fixed:** the "inside T_f(t)" check allowed changes up to 1e-6 (signed-log units) off the
  support; on features with tiny sd that is 0.001 standardised units, so a file could be counted as covered while
  outside the box (found by `test_families`). Now: exactly zero off the support, 1e-9 rounding tolerance on it, in
  `edit_families.inside`, `run_all.corpus_soundness` and the test. Family test: 4,336 cases inside, 4,040 certified,
  0 flipped. All 19 unit tests pass.
- **2-27** `[A2, A5]` 2i script now defaults to the family split. Smoke test on it (1 epoch, first grid point,
  validation): MLP accuracy 90.9% (TPR 80.7%); per-view LightGBM main 92.1%, FPR 0.6%, certified score 37.9%;
  second 90.8%, score 66.9%; aligned7 MLP views 82.5%; uniform / box CROWN-IBP 96.9 / 96.6%, certified over T_f(1) 0%;
  edit-aware 90.2%, FPR 5.5%, mean certified over T_f(1) 15.8%. One epoch: says only that the pipeline runs.
  Grid command (family split, about 35–40 min) in `RUN_NEXT.md`.

### Decisions 2026-11-13 (author; logged before implementation)
- **2-28** `[A1, A3]` Log 2-23 confirmed: all five hashed section blocks are structural.
- **2-29** `[A5, B4]` **Family assignment category by category, for every split (3b).** Each family gets the
  majority category of its malware; within each category, families are visited in seeded random order and each
  goes to the part furthest below that category's target share (relative). Benign files are split at random.
- **2-30** `[A5, B6]` **2i tuning by grouped 3-fold cross-validation** over train + validation of the seed-0 family
  split. The pooled families are assigned to 3 folds category by category (same rule, equal targets); benign
  files to 3 random folds. For each grid point: train on 2 folds, evaluate on the third, three times;
  standardisation (and the family sets' sd) fitted on the 2 training folds. Score = mean over folds of the
  metrics of 2-17 (FPR cap applied to the mean FPR). The test part is never used.

- **2-31** `[A5, B4]` **Category-by-category assignment implemented** (`assign_families`, used by `family_split`
  and `family_folds` in `malcert/data.py`). A first version (random family order, relative deficit) missed the size
  targets (validation 25.7% of malware); fixed by visiting families roughly largest first (size × random factor) into
  the part with the largest absolute deficit, ties broken at random. The random factor width was chosen on split
  balance only (5 seeds, no model): (0.8, 1.25) gave the smallest worst share error (2.7 points) with seeds still
  differing (test-family overlap 0.31; (1, 1) gives 0.99). Worst category-mix error stays about 10 points for every
  width: whole families of about 1,000 samples cannot be split. Seed 0, malware (share) and mix trojan / worm /
  backdoor / other: whole 12,773, 52.2 / 29.1 / 12.8 / 5.8%; train 8,987 (70.4%), 50.5 / 30.2 / 12.3 / 7.0;
  val 1,266 (9.9%), 59.3 / 22.4 / 16.4 / 2.0; test 2,520 (19.7%), 55.0 / 28.6 / 12.7 / 3.7. Folds over train + val
  (10,253 malware, mix 51.6 / 29.3 / 12.8 / 6.3): 3,636 (35.5%), 50.7 / 28.8 / 19.0 / 1.5; 3,356 (32.7%),
  51.7 / 31.6 / 5.3 / 11.5; 3,261 (31.8%), 52.4 / 27.4 / 13.6 / 6.5. `tests/test_split.py`: 3 tests (shares within
  3.5 points, large-category mix within 13 points, folds partition train + val exactly and never touch test).
- **2-32** `[A2, A5]` `tools/tune_validation.py` now runs grouped 3-fold CV (log 2-30). Smoke test (1 epoch, first grid
  point, 3 folds, 4.5 min): mean accuracy MLP 91.5% (folds 86.1 / 94.2 / 94.3), per-view LightGBM main 95.0%
  (FPR 0.4%, score 31.7), second 94.0% (score 66.1), aligned7 MLP views 89.8% (FPR 7.0%), uniform / box CROWN-IBP
  90.8 / 91.0% with 0 certified over T_f(1), edit-aware 85.9% (FPR 4.6%, mean certified over T_f(1) 18.0%).
  Full grid: about 70–80 min; command in `RUN_NEXT.md`. All 20 unit tests pass.

- **2-33** `[A2, A5]` **2i grid run** (author, `results_tuning/`, grouped 3-fold CV, family split seed 0; fold means)
  and **frozen settings** (`config.py`):
  - MLP: lr 1e-3, 30 epochs (94.3% accuracy; 3e-4/60: 93.9%) → unchanged defaults.
  - Per-view LightGBM main: 200 trees, 64 leaves (93.6%, FPR 0.30%, score 35.1; 200/31 had 95.0% but 31.7).
  - Per-view LightGBM second: 200 trees, 64 leaves (93.2%, FPR 0.65%, score 67.2).
  - aligned7 MLP views: 90 epochs (93.6%, FPR 1.98%; no setting met 1%, lowest FPR taken) → `ablation_configs`
    gets a 4th field, view epochs.
  - Uniform-ball CROWN-IBP: ε_train 0.1. Both settings certify 0.00% over T_f(1); the rule did not specify ties,
    resolved by the higher validation accuracy (95.0 vs 94.7%) → `unc_train_eps` = 0.1.
  - Box CROWN-IBP: ε_train 0.1 (0.01% vs 0.00% over T_f(1)) → new field `box_train_eps` = 0.1; `ibp_train_eps`
    stays 0.05 as the reporting budget of the original C3 rule.
  - Edit-aware CROWN-IBP: t_train 0.5, mean (92.3%, FPR 1.67%, certified over T_f(1) 65.8%; no setting met 1%,
    lowest FPR taken; t 1.0 / mean certified 76.2% at FPR 2.49%).
  - Observation for Stage 4: uniform and box CROWN-IBP certify essentially nothing over the edit-family sets; the
    family sets are far larger than ε = 0.1 in standardised units (median ε needed by real edits 0.2–28).
  Unit tests pass (20). No pilot run yet with the frozen settings (Stage 3 starts with one).

### Ideas not done
- Execution check of edited binaries in a sandboxed VM (would turn "plausibly functionality-preserving" into
  "verified"); out of the lean scope.

### Tests
- **1-10** `[A1, B1]` `tests/test_threat_model.py` (9 tests since 1i): units tile the vector and respect groups;
  annotation well-formed; natural bounds hold on BODMAS; box not clipped at the training maximum; attack
  projection and certificate box describe the same set; every in-scope edited file is inside the threat set
  (groups, and box at the ε it needs); frozen annotation equals the evidence rule; block bookkeeping of
  `run_all.py`.
