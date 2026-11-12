# Revision plan: pre-submission review (two reviewers)

The paper has **not been submitted yet**. These comments come from two professors who reviewed the draft, so every fix goes in before the first submission. Target: an Elsevier journal (Computers & Security), `elsarticle` template.

Put this file in the project root. Work **one stage at a time**. After each stage, stop, report what changed, and wait for approval.

Comment IDs used throughout:
- **A1–A6, Am1–Am7**: Reviewer A, main comments 1–6 and minor comments 1–7.
- **B1–B8**: Reviewer B, major comments 1–8.

Keep a running `REVISION_LOG.md`: one entry per change, tagged with the comment IDs it answers.
No response letter is written in this revision; the log keeps the comment-to-change mapping in case one is needed later.

General rules (in addition to CLAUDE.md):
- Every number in the paper comes from macros. New analyses write their own `numbers_*.tex`.
- Run the `quick` preset as a pilot after every code change. Never launch a long run without a passing pilot and passing tests.
- Any change to the threat model or a certificate needs a test in `tests/`. `violations` must stay 0 everywhere.
- Choices that could be tuned (grouping, LightGBM size, thresholds) are fixed from the validation split or from the Stage-1 edit map, never from test results. Record each choice and its basis in the log.
- Report negative results as plainly as positive ones.

## Where each comment is handled

| Comment | Topic | Stage |
|---|---|---|
| A1, B1, B2 | Threat-model validity, real edits, scope of soundness | 1, 4a |
| A2 | Baselines and fair comparison | 2c–2e |
| A3, B5 | Group certificate: tightness, grouping, keep sizes, cost | 2a, 2b, 2f |
| A4 | Abstract/text mismatches, runtimes, code release | 2f, 4 |
| A5, B6 | Seeds, intervals, significance | 3a |
| A5, B4 | Family leakage and duplicates | 3b |
| A5, B3 | Subset, second dataset, generalizability | 3e, 3f |
| A5, B7, Am4, Am5 | Temporal windows, drift vs composition, update frequency | 3c |
| A6, B8 | Reproducibility, editorial placeholders | 4b, 4c |
| Am1–Am3, Am6, Am7 | Minor items | 1f, 4 |

---

## Stage 0: housekeeping (about 1 hour)
1. Commit the reviewed draft, tag it `draft-v1`, and create branch `revision-1`.
2. Copy `results_full/` and `results_temporal/` to `results_draft_v1/`.
7. Update the author line in `CLAUDE.md`: the sole author is Md. Musfiqur Rahman.
3. **Resume support.** `run_all.py` must skip seeds already present in `<out_dir>/results.json`, so an interrupted overnight run continues instead of restarting.
4. **Provenance.** Each `results.json` records the git commit hash, package versions, device, and wall-clock time per experiment block.
5. **Pinned environment.** Write `environment.yml` and `requirements-lock.txt` (`pip freeze`) for the `malcert` env.
6. Add a `--blocks` option to `run_all.py` so a run can execute only some experiment blocks (e.g. clean + ablation + certified training, without smoothing). The temporal and full-data runs need this.

---

## Stage 1: problem-space check and threat-model repair (A1, B1, B2, A3, Am2). Everything else depends on this.

**Why first.** Both reviewers ask how the immutable / mutable / monotone annotation was established and whether it matches real PE modifications. The honest answer today is "by reasoning, not by measurement", and two parts of it are wrong:
- adding a section or an import also changes header and data-directory fields that are marked immutable;
- the box was clipped to the training-set range, which is unsound, since an attacker can exceed any training value.

Every certificate number changes once this is fixed.

### 1a. Environment
- Separate conda env `malcert-ps` (Python 3.8) with `lief==0.10.1` and the `ember` package (`pip install git+https://github.com/elastic/ember`). The EMBER README states that LIEF 0.10.1 gives consistent version-2 features on Windows.
- If `lief==0.10.1` will not install, use the closest version that does, and record which one.
- Sanity check: extract features for a few files twice and confirm identical vectors.

### 1b. Corpus (benign files only; no malware ever)
- Copy 100 benign `.exe`/`.dll` files from `C:\Windows\System32` into `D:\...\ps_corpus\orig\`. Copy only; never touch system files. Use the D: drive.
- Skip files LIEF cannot parse. Record the final count and the size range.
- Why benign files are enough: the question is *which features an edit changes*, which does not depend on whether the file is malicious. State this in the paper as a limitation too.

### 1c. Edits
Each edit writes a new file to `ps_corpus/edited/<edit>/`; originals are never changed. **Never execute edited binaries.**

| Code | Edit | Variants | In scope? |
|---|---|---|---|
| E1 | Append overlay | 1 KB, 64 KB, 1 MB; random bytes and benign-file bytes | yes |
| E2 | Append printable strings (URLs, paths, registry keys) | 50 and 500 strings | yes |
| E3 | Add a section (LIEF) | 4 KB and 64 KB; random and benign content | yes |
| E4 | Add imports (LIEF) | 1 and 10 `kernel32.dll` functions not already imported | yes |
| E5 | Edit the COFF timestamp | a random date | yes |
| E6 | Rename sections | random 8-character names | yes |
| E7 | Header-field edits that loaders ignore | optional-header checksum; DOS-header slack bytes | yes |
| E8 | Strip debug directory and embedded signature, where present | n/a | decide from evidence |
| E9 | Pack with UPX | default settings | no; measured to show why |

- E1–E7 are the functionality-preserving manipulations catalogued by Demetrio et al. (2021) and used as actions by Anderson et al. (2018, "Learning to evade static PE machine learning malware models via reinforcement learning"). Verify that second reference in Google Scholar before citing.
- E8 matters because it *removes* content: it tests whether "increase-only" features can in fact decrease.
- E9 (download UPX from its official GitHub releases) is expected to change almost every group. It is measured only to document, with numbers, what lies outside the threat model.
- Check every edited file re-parses with LIEF. The paper states that functionality was not verified by execution.

### 1d. Measure
- Extract EMBER v2 features (`PEFeatureExtractor(feature_version=2)`) from originals and edited files.
- Standardize both with the BODMAS training statistics (seed 0).
- Report per edit type, in `ps_results/edit_map.csv` and `paper/tables/tab_edit_map.tex` (from `tools/problem_space.py`):
  1. which features change, and in what share of files;
  2. how many of the 9 groups the edit touches (median and max);
  3. whether every changed feature is annotated mutable, and whether every monotone feature only increased;
  4. the L-infinity size of the change in standardized units, i.e. the epsilon the edit needs (median and 90th percentile);
  5. the share of edited files whose vector lies inside the *current* threat set and inside the *repaired* one (1e).

### 1e. Repair the threat model
1. **Re-annotate `threat_masks()` from evidence.**
   - Mutable: every feature observed to change under the in-scope edits.
   - Monotone: only counts and sizes that never decreased under any in-scope edit.
   - Decide from the measurements whether `Header(static)` and `DataDir` remain immutable groups. If any in-scope edit changes them, they become attackable groups and count toward r.
2. **Annotation table with justification (B1).** Generate, per EMBER feature block: the rule applied, the edits observed to change it, and a literature reference. This becomes Appendix C and a short summary table in Section 3.
3. **Remove the training-range clip** from `input_box` and `Constraints.project`. Keep only natural bounds, each verified from the data:
   - byte and byte-entropy histograms are normalized (rows sum to 1), so each bin lies in [0, 1];
   - counts and sizes cannot go below transform(0);
   - hashed features (imports, exports, section names) are signed, so they get no bound and are never monotone.
4. **Tests.** Add a test that every in-scope edited vector from 1d lies inside the repaired threat set (group sets for the group certificate; the box at the epsilon the edit needs). Rerun all tests and the quick pilot.

### 1f. Epsilon in real units (Am2)
- `tools/eps_units.py`: for a median test sample, the raw change that epsilon = 0.01, 0.05 and 0.1 allows on readable features: file size, number of strings, number of imports, number of sections, one byte-histogram bin.
- Put it next to the epsilon each real edit needs (1d.4). This shows honestly how small an edit the L-infinity certificate covers.

### 1g. Coverage table of evasion techniques (B2)
One table for the paper, filled from 1d: technique → covered / partly covered / out of scope → evidence.
- Expected covered: overlay append, string padding, section injection, import addition, timestamp and section-name edits.
- Expected out of scope: packing (E9), repacking, code obfuscation and metamorphism, dropper wrapping. State these explicitly.

**Stop and report:** the edit map, the coverage table, every annotation change with its reason, the new mutable/monotone counts and attackable groups, and how the pilot numbers moved against `results_draft_v1`.

---

## Stage 2: method changes (A2, A3, B5)

### 2a. Exact group certificate and ceiling (A3)
- **Exact worst case.** For every set A of r attackable groups, treat every view that keeps a group in A as voting for the wrong class. Certify iff, for all A, (true-class votes among untouched views) > (wrong-class votes among untouched views) + (touched views). Report it next to the 2·Delta bound.
  - Pre-check on BODMAS (seed 0): the gain is at most 0.1 points, because the worst-case attacker picks groups whose views vote correctly. Report this honestly.
  - Test: brute-force agreement on a small synthetic vote table.
- **Ceiling.** (k, r) is certifiable only if C(G−r, k) > C(G, k) − C(G−r, k). For G = 9:

  | k | Views | Largest certifiable r |
  |---|---|---|
  | 1 | 9 | 4 |
  | 2 | 36 | 2 |
  | 3 | 84 | 1 |
  | 4 | 126 | 1 |
  | 5 or more | 126 or fewer | 0 |

  - k = 3, r = 2 is impossible for any vote-counting certificate (35 untouched views cannot outvote 49 touched ones). Add the statement and proof to the paper.
  - This table also **justifies the keep sizes (B5)**: k ≥ 5 certifies nothing. Add **k = 4** to the experiments (MLP base only), so the full useful range k = 1..4 is covered.
- **Why k = 1 gives zero at r = 4.** It needs all 9 views to vote malware. Pre-check: the Exports-only view votes malware for 0.6% of test malware, since most PE files export nothing; unanimity occurred for 0.00%. Compute per-view vote rates in `make_figures.py` and report them.

### 2b. Grouping: justification and edit-aligned variant (A3, B5)
- **State where the 9 groups come from:** they are the feature blocks defined by the EMBER extractor itself, not chosen by us; the only change is moving the timestamp. Say so in Section 3.
- **Edit-aligned grouping.** Using only the Stage-1 edit map, define groups so each in-scope edit touches as few groups as possible. Candidates: merge byte histogram + byte entropy + strings + size fields into "content"; merge import-related data-directory entries into Imports; fold Exports into another group.
- Report both groupings, and a table: real edit → groups touched → certified detection at that r.
- **Sensitivity.** Report how certified detection and clean accuracy change with grouping and k (one table), so the effect of these choices is visible.
- **Generalization (text only).** The method needs only a partition of features into blocks tied to file components. Discuss EMBER v3 / EMBER2024 and SOREL-20M, whose extractors expose the same block structure.

### 2c. LightGBM as base classifier (A2)
- One LightGBM per view for k = 1, 2, 3 (9 / 36 / 84 models). Theorem 1 only counts votes, so per-view classifiers keep it valid.
- Choose `n_estimators` on the validation split; if k = 3 is too slow, reduce it and say so.
- Report clean metrics, certified TPR and training time.

### 2d. Fair certified-training baseline (A2)
- Add CROWN-IBP trained on the **unconstrained** L-infinity ball.
- Report a 2 × 2 table: training box × certification box.
- The contribution claimed is constrained-trained vs unconstrained-trained, both certified on the constrained box. The certification-box effect is attributed to Proposition 1.

### 2e. Baselines from prior work (A2)
- **Monotonic classifier (Incer et al. 2018):** LightGBM with `monotone_constraints=+1` on the increase-only features.
- **Giri et al. (2026):** re-implement their training (Gaussian noise on part of the features plus random group ablation). Certify the L2 radius with our CERTIFY and label it a re-implementation.
- Run the **group-transplant attack against every model**, in one uniform table.

### 2f. Cost (A4, B5)
- On the GTX 1050 Ti: training wall-clock per model; certification time per sample per certificate; number of forward passes per sample as a function of k.
- One runtime table. Replace the word "cheap" with the measured numbers.

**Stop and report:** quick-pilot results and timings for everything in Stage 2, and a revised compute estimate for Stage 3.

---

## Stage 3: data and statistics (A5, B3, B4, B6, B7)

### 3a. Seeds, intervals, tests (A5, B6)
- 10 seeds for the main splits.
- Report mean ± std and 95% t-intervals.
- Model-vs-model comparisons use **paired** differences across seeds: 95% t-interval plus a paired t-test, with Holm correction across the main comparisons. List those comparisons in advance in the log.
- Replace "positive in every seed" and "N combined standard deviations" with interval statements.
- Note in the paper that the 30K subset is fixed; seeds vary the split and the training.

### 3b. Leakage audit and family-disjoint split (A5, B4)
- **Audit (`tools/leakage_audit.py`), reported in the paper.** Pre-check values to reproduce:
  - exact duplicate feature vectors: 14 rows in all of BODMAS, none with conflicting labels, no duplicate hashes; 0 test rows with an exact twin in training;
  - family overlap under the random split: 98.4% of test malware belong to a family also present in training;
  - near-duplicates: 23.3% of test malware have a training neighbour within L2 distance 0.1 in standardized space (benign: 4.1%); the median nearest-neighbour distance is 0.78 for malware and 9.84 for benign.
  - Conclusion to state: exact duplication is negligible, but near-variant leakage under the random split is real.
- **Family-disjoint split = new main split.** Each malware family goes wholly to train, val or test. Benign files have no family label and are split at random.
  - Families are very uneven (the 5 largest hold 35% of malware; 127 have one sample). Assign families greedily so each seed's test set is close to 20% and keeps both classes; report per-seed sizes and category mix.
- **Near-duplicate sensitivity.** Also report main metrics on the test set with near-twins removed (nearest training neighbour within L2 0.1), for malware and benign. This covers benign files, which the family split cannot.
- The random split stays, for comparison with earlier BODMAS/EMBER work.

### 3c. Temporal evaluation (A5, B7, Am4, Am5)
BODMAS has malware from 2019-08 to 2020-09, with 2,500–5,400 malware and 2,500–8,200 benign per month from 2019-09 on; before 2019-08 there are 10,731 benign files and no malware.
- **Use the full dataset for this block** (certification is cheap enough without smoothing; use `--blocks`), 3 seeds.
- **Decay curve.** Train on everything up to a cut-off month; test separately on each later month. Cut-offs: 2019-12, 2020-02, 2020-04, 2020-06. Plot clean and certified detection against months since training.
- **Update frequency.** From the decay curves, report how many months pass before certified detection falls below a stated level (e.g. 90% of its in-distribution value), and compare "train once" with "retrain every 2 months". This answers how often models and certificates must be refreshed.
- Report train and test sizes for every window. Require at least 300 malware and 300 benign per test month.
- **Composition vs drift.** Reweight the in-distribution per-category TPR to each test month's category mix: composition effect = reweighted − in-distribution; drift effect = temporal − reweighted.
- State the benign-date caveat (benign files date back to 2007) in the paper.

### 3d. Smoothing on the full test set (A5)
- Time one seed first. Certify every test point if it fits in about 2 h per seed; otherwise all points for 3 seeds, and say so.
- Smoothing is now a baseline (Am1).

### 3e. Subset: justification and representativeness (A5, B3)
- **Representativeness table:** 30K subset vs full BODMAS on class ratio, category shares, number of families covered, and month distribution.
- **Subset-draw sensitivity:** repeat the main clean and certified metrics on 3 different random 30K draws (1 seed each).
- **Full-data check:** all 134,435 samples, 3 seeds, family split: clean metrics, group certificates, CROWN-IBP at ε = 0.05. State whether the conclusions match.
- Justify the 30K subset with the measured certification cost (2f).

### 3f. Second dataset: optional, decide after timing (A5, B3)
- EMBER 2018 (feature version 2, LIEF 0.9.0), `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2`. Download and vectorize on D:.
- 30K stratified sample, 3 seeds, within-dataset only. Never mix it with BODMAS: the BODMAS paper does not state its LIEF version.
- If disk space or time does not allow, add a generalizability paragraph instead, pointing to 3c and 3e.
- SOREL-20M is not used: different feature version, terabytes of data.

---

## Stage 4: manuscript, reproducibility, final audit

### 4a. Text and figures
1. **Soundness wording (A1, B1, B2).** Replace every "sound for the real attacker" with the exact scope: the in-scope edits measured on N benign files. Explain "over-approximation" precisely: the threat set contains every feature vector those edits produced, plus many they cannot. Make the Introduction and Section 7 agree; use the coverage table from 1g.
2. **Contributions.** C1 becomes "a problem-space-validated threat model". Smoothing is demoted to a baseline (Am1). Adjust the title only if it no longer matches.
3. **The 93.9% (A4).** Separate macros for the standard-MLP evasion rate under the group attack (stated in §6.2) and the ablation detector's empirical detection (§6.3). The abstract cites the MLP one.
4. **Table 1 (A4).** Add the standard 2381–256–256–2 network row.
5. **Figure 5 (Am3, B6).** Wilson 95% intervals per cell; merge categories with fewer than 30 distinct test files into "other".
6. **Practical deployment (B7).** A Discussion paragraph built on 3c: what the decay curves imply for retraining and re-certifying.
7. **Generalizability (B3)** and **grouping generality (B5)** paragraphs.
8. **Citations (Am7).** Lucas et al. 2023 (USENIX Security); Chen et al. 2019 (NeurIPS, tree verification); Kantchelian et al. 2016 (ICML); Anderson et al. 2018 (RL evasion), after checking each in Google Scholar. Mention that tree verification could certify LightGBM under L-infinity directly.
9. **Template (Am6).** Keep Elsevier `elsarticle`; remove any wording that suggests another publisher's review style.

### 4b. Reproducibility (A6, B8)
- **Appendix A:** every hyperparameter per model (epochs, learning rate, batch size, optimizer, warm-up, the κ, β and ε schedules). Generated from `config.py`.
- **Appendix B:** attack settings (steps, step size, restarts, random start, donors) and **certification procedures as pseudo-code**: group-ablation certify (bound and exact), CROWN/IBP verify, and smoothing CERTIFY with n0, n, alpha and the abstain rule.
- **Appendix C:** the full feature annotation with justification (from 1e).
- **`reproduce.md` + one script** that reruns every experiment and rebuilds every table and figure from a clean checkout.
- **Code release.** Push to a private GitHub repository now and put its link in the Data availability statement. At submission time: make it public if the journal's review is single-anonymized; if double-anonymized, use an anonymous mirror (anonymous.4open.science) with author names removed from code, LICENSE, CLAUDE.md, logs and paths.

### 4c. Final audit: do this last
1. All `violations` are 0 in every results file; all tests pass.
2. No `%CHECK` sentence is left unverified; every qualitative sentence matches the new numbers.
3. Every macro used is defined; no hand-typed result numbers (grep the `.tex` files for digits followed by `\%`).
4. Abstract ≤ 250 words; highlights updated and each ≤ 85 characters.
5. Every figure and table is referenced in the text and sits in its own section.
6. **Editorial items (A6, B8).**
   - Sole author: **Md. Musfiqur Rahman**, corresponding author, email `musfiqurtonmoy@gmail.com`. Keep the affiliation already on the title page.
   - CRediT statement: the same single name, with all roles (Conceptualization, Methodology, Software, Investigation, Writing – original draft). Check that no other author name remains anywhere in the paper, LICENSE or README.
   - Generative-AI declaration: **do not write it.** Leave the section with its visible red placeholder; the author will write it himself. Report it as the one open item.
7. Rebuild `paper_overleaf.zip` and report the list of changed sections.

---

## Compute estimate (GTX 1050 Ti)
The draft-v1 runs cost about 14 min per seed per split. With the Stage 2 additions expect 35–40 min; measure after the Stage 2 pilot and revise.
- 10 seeds × (random + family) ≈ 12–13 h
- temporal decay curves on full data (4 cut-offs × 3 seeds, no smoothing) ≈ 5–8 h
- full-data check + subset draws ≈ 5–7 h
- full-test-set smoothing: time it first
Plan for 3–4 overnight runs, started one after another with resume support. Keep the PC from sleeping.
