# Stage 4 outline (plan only; no manuscript edits yet)

Numbers below are the final Stage 3 values, for orientation. In the paper every number is a macro;
macros marked **(new)** must be added to the script named before the text is written.

## Title

Kept unchanged, since the pre-registered C3 rule was met (REVISION_PLAN 2g):

> Certified Robustness of Machine-Learning Malware Detectors in Constrained PE Feature Space:
> Group-Ablation Certificates and Constraint-Aware Certified Training

Section 4 defines edit-aware training as the constraint-aware method. Optional small change, only if the author wants it:
"... Edit-Aligned Group-Ablation Certificates and Edit-Aware Certified Training".

## Wording rules (author, 2026-11-14)

- The family-disjoint split is the main result everywhere. Random-split numbers appear only as a comparison with
  earlier work, and to show by how much the random split overstates.
- Cost of certification: "\CmpFAbs{} points, not significant" with its interval \CmpFInt, Holm p = \CmpFP.
  Every comparison interval is written with its one macro `\Cmp<X>Int` (from `stats.py`), never assembled from
  `Lo`/`Hi` by hand.
- Box-constrained CROWN-IBP is reported as a **negative ablation**: +\CmpBDiff{} points \CmpBInt, p = \CmpBP.
- Intervals, not "positive in every seed" or "N combined standard deviations"; say that 5 seeds give wide intervals.
- Every L-infinity certified-training number is followed by its coverage (\PsEpsLeTrainPct\% of measured edits at ε = 0.05).

## Contributions (plan 2g, final 5-seed numbers, family split)

1. **Problem-space-validated threat model.** 150 benign PE files (PE32+ and PE32), 10 edit types, 4,169 in-scope
   edited files. All of them lie inside the repaired threat set (draft v1: \PsDraftBoxInsidePct\% inside its box).
   2,314 mutable and 9 increase-only features. An edit map gives the groups touched and the ε needed per edit, and a
   three-level coverage table. Answers A1, B1, B2, Am2.
2. **Edit-aligned group certificates.**
   - Exact worst-case certificate and the ceiling r < f(G, k), which also justifies the keep sizes.
   - EMBER's own groups certify 9.0% averaged over the 9 edit types; aligned5 k = 2 gives +11.3 points
     [7.6, 15.1], Holm p = 0.004 (`\CmpC*`).
   - Headline detector, per-view LightGBM: 55.1% certified at r = 1 [45.7, 64.4], against 36.6% for MLP views
     (+18.5 [8.4, 28.6], p = 0.021). Under the group attack at r = 1 it detects 62.6%, where plain LightGBM detects 0%
     (+62.6 [47.4, 77.8], p = 0.002).
   - Clean accuracy 92.8% against 94.6%: 1.8 points, not significant, \CmpFInt (= [−4.1, 0.6]; an earlier hand-typed
     "−4.2" here was a rounding slip), p = 0.20.
   - Answers A2, A3, B5.
3. **Edit-aware certified training** (wording per REVISION_PLAN "3g result and C3 wording").
   - Threat sets T_f(t) are built from the measured edit families. Edit-aware CROWN-IBP certifies \SwEditCert\% of
     malware over T_f(1), at \SwEditFpr\% FPR.
   - **Trade-off at matched FPR.** Uniform-ball training reaches comparable certified detection only at ε = 1
     (\SwUnifOneCert\%), at \SwUnifOneFpr\% FPR. At an FPR no higher than edit-aware's, it certifies at most
     \SwUnifLowFprCert\% (ε = \SwUnifLowFprEps). The best uniform ε was chosen after the fact on test data, which
     favours the baseline, and it is still not significantly better or worse: \SwBestDiff{} points
     [\SwBestLo, \SwBestHi].
   - **Complementary by edit family.** Uniform ε = 1 is better on content (\SwUnifOneContent{} vs \SwEditContent)
     and strip (\SwUnifOneStrip{} vs \SwEditStrip). Edit-aware is better on section (\SwEditSection{} vs
     \SwUnifOneSection) and import (\SwEditImport{} vs \SwUnifOneImport).
   - **Pre-registered result:** C3 rule met, +\CmpADiff{} points [\CmpALo, \CmpAHi], Holm p = \CmpAP. The same holds
     at matched accuracy (+\SwMatchedDiff). The text says that the 2i grid for the uniform baseline ({0.05, 0.1}) was
     too narrow and that the sweep (3g) was added to correct it.
   - Never "uniform-ball certifies 0%" as the headline contrast.
   - Box-constrained training is no better than uniform-ball training at ε = 0.05 (negative ablation).
   - Answers A2, A3.
4. **Evaluation that does not overstate** (answers A5, B4, B6, B7). Family-disjoint split, 5 seeds, paired intervals,
   Holm correction across 6 pre-registered comparisons, and a temporal decay analysis.
   - Random splits overstate certified detection by \RandFamGapMin{} to \RandFamGapMax{} points, depending on the model.
   - Certified detection falls below 90% of its first-month value within \TdMonthsMin–\TdMonthsMax{} months.
     Retraining recovers \TdRetrainGainMin–\TdRetrainGainMax{} points.

## Abstract (as in `main.tex`; all numbers are macros)

Machine-learning malware detectors can be evaded by small, functionality-preserving edits to a Portable Executable
(PE) file. A certified defence holds only for the threat model it assumes, so we first measure what real edits change.
We apply \PsNEditTypesInScope{} edit types to \PsNFiles{} benign PE files. All \PsNEditedInScope{} edited feature
vectors lie inside our repaired threat model, against \PsDraftBoxInsidePct\% for a conventional per-feature box. No
edit touches only one EMBER feature group, and an $\ell_\infty$ ball of the radius common in certified training
contains only \PsEpsLeTrainPct\% of the edits. We therefore align the groups of a group-ablation certificate with the
measured edits, and train networks against threat sets shaped like the measured edit families. On a family-disjoint
split of BODMAS (\NSeedsFam{} seeds, 95\% intervals), a per-view LightGBM detector certifies \FamCertROneLgbmViews\%
of test malware against any change confined to one edit-aligned group. Its clean accuracy is \CmpFAbs{} points
below LightGBM, a difference that is not significant. Under a group-transplant attack it detects
\FamGattackLgbmViews\% of malware, LightGBM \FamGattackLgbm\%. Edit-aware certified training certifies \SwEditCert\%
of malware over the measured edit families at a \SwEditFpr\% false-positive rate. Uniform-ball training matches it
only at \SwUnifOneFpr\% false positives, and the two are complementary across edit families. The pre-registered gain
over the validation-tuned uniform baseline, +\CmpADiff{} points, is larger, because that baseline's tuning grid was
too narrow. Random train/test splits overstate certified robustness by \RandFamGapMin{} to \RandFamGapMax{} points
depending on the model.

**New macros (Stage 4a, step 1):**
- `stats.py` → `numbers_stats.tex`: `\NSeedsFam`, `\NSeedsRand`, `\CmpFAbs`, `\RandFamGapMin` / `\RandFamGapMax`
  (certified-detection metrics at ≥ 1% on either split), and `\Fam<Stem>` / `\Rand<Stem>` with `Lo` / `Hi` for every
  model metric (stems in `MACRO`, e.g. `CertROneLgbmViews`, `GattackLgbmViews`, `CertTOneEdit`, `AccLgbm`).
- `eps_sweep.py --analyse` → `numbers_sweep.tex`: `\SwEditCert` / `Fpr` / `Acc`, `\SwUnifOneCert` / `Fpr` / `Acc`,
  per family `\SwEdit<Family>` / `\SwUnifOne<Family>`, `\SwUnifLowFprCert` / `Eps` / `Fpr` (best uniform model whose
  mean FPR does not exceed edit-aware's: the "matched FPR" reading of "FPR near 1%"), `\SwBestDiff` / `Lo` / `Hi` / `P`,
  `\SwCollapseEps`, `\SwNModels`, `\SwRadiusUnit`, `\SwRadiusUnitNTrain`, `\SwRadiusSectionSd`.
- `temporal_decay.py` → `numbers_decay.tex`: `\TdCutA` / `B`, `\TdFirst<Model><A|B>`, `\TdMonthsMin` / `Max`,
  `\TdRetrainGainMin` / `Max` (mean over the \TdNCommonMonths{} months both cut-offs test), `\TdDriftMin` / `Max`,
  `\TdCompMin` / `Max`.
- Not needed after all: `\PsNFilesAll` and `\PsNEditedInScopeAll`, because `\PsNFiles` (150) and
  `\PsNEditedInScope` (4,169) already cover both architectures.

## Sections

| § | Contents | Tables / figures | Comments |
|---|---|---|---|
| 1 Introduction | Problem; why the threat model must be measured; the four contributions; exact soundness scope ("the in-scope edits measured on N benign files"; over-approximation defined) | – | A1, B1, B2, A4 |
| 2 Related work | Feature-space vs problem-space attacks (Anderson et al. 2018, Lucas et al. 2023); certified defences (randomized smoothing, Giri et al., IBP/CROWN-IBP); monotonic classifiers (Incer et al.); tree verification (Kantchelian et al. 2016, Chen et al. 2019), which could certify LightGBM under L-infinity directly | – | Am7, A2 |
| 3 Threat model and problem-space validation | Corpus and edits E1–E10 (E9 UPX and E0 controls); feature units, natural bounds, repaired annotation (why the clip was unsound); Proposition 1 (certifying on the box is sound); edit map; ε in real units; L∞ coverage; coverage table (3 levels) | tab_edit_map, tab_annotation, tab_eps_units, tab_coverage, fig_eps_coverage | A1, B1, B2, Am2 |
| 4 Methods | 4.1 Exact group certificate, 2Δ bound, ceiling theorem with the k = 3, r = 2 impossibility proof, keep sizes. 4.2 Edit-aligned grouping procedure, candidates, pre-registered selection, the weakest view. 4.3 Per-view LightGBM (Theorem 1 only counts votes). 4.4 Edit families, T_f(t), edit-aware CROWN-IBP; box-constrained variant. 4.5 Baselines: standard MLP, PGD-AT, monotonic LightGBM, Giri re-implementation, isotropic smoothing | ceiling table (inline), fig_group_cert schematic | A2, A3, B5, Am1 |
| 5 Experimental setup | BODMAS 30K subset and why (memory and cost, representativeness, full-data check); family-disjoint split by category, leakage audit; tuning by grouped 3-fold CV on train + val; seeds and statistics, the 6 pre-registered comparisons; hardware | tab_representativeness, tab_runtime | A4, A5, B3, B4, B6, B5 |
| 6 Results | 6.1 Clean accuracy (incl. 2381–256–256–2 row). 6.2 Group-transplant attack on all models (MLP evasion macro separate from ablation detection). 6.3 Group certificates per edit type, EMBER vs aligned, sensitivity to grouping/k, per-view vote rates. 6.4 Certified training: edit-aware vs uniform vs box, coverage of T_f(t), box ablation (negative). 6.5 Pre-registered comparisons. 6.6 Random vs family split, near-duplicate sensitivity, full-data check. 6.7 Temporal decay and retraining, composition vs drift. 6.8 Smoothing baseline | tab_clean, tab_attacks, tab_group_cert, tab_certified_training, **tab_comparisons (new)**, **tab_split_gap (new)**, tab_temporal_cert, tab_temporal_clean, **fig_decay (new)**, fig_per_category (Wilson intervals, categories < 30 merged), tab_smoothing | A2, A3, A4, A5, B4, B5, B6, B7, Am1, Am3, Am4, Am5 |
| 7 Discussion and limitations | Scope of soundness; what L∞ certificates cover (\PsEpsLeTrainPct\%); deployment: retraining and re-certifying cadence from 6.7; generalizability (single dataset; EMBER 2018, SOREL-20M as future work); grouping generality for other extractors; edits not verified by execution; benign-date caveat; E3/E4/E8 not certifiable | – | A1, B1, B2, B3, B5, B7 |
| 8 Conclusion | Contributions restated with headline macros | – | A4 |
| Back matter | CRediT (sole author, all roles); competing interest; data availability (private GitHub now, public or anonymous mirror at submission); generative-AI declaration **left as the red placeholder for the author** | – | A6, B8 |

## Appendices

- **A. Hyperparameters**, per model, generated from `config.py` (A6, B8).
- **B. Attack settings and certification pseudo-code**: group-ablation certify (bound and exact), CROWN/IBP verify on
  the box and on T_f(t), smoothing CERTIFY (n0, n, α, abstain rule); deviations of the Giri re-implementation (A6, B8, A2).
- **C. Full feature annotation**, with evidence and "conservative, not observed" labels (`tab_annotation_full`) (B1).
- **D. Problem-space details**: per-architecture edit map (`tab_edit_map_arch`); E0 rebuild controls; the
  has_relocations artefact; extractor compatibility check (`numbers_xc`); T_f coverage before and after the interval
  rule (A1, B1).
- **E. Grouping candidates and validation selection**; the exact certificate vs the 2Δ bound (A3, B5).
- **F. Tuning grids and chosen settings**, from the grouped CV (A5).

## Removed from the draft

- Plain IBP and asymmetric CROWN-IBP, with their macros (`\CrownAsym*`, `\IbpCert`, `\AsymGainSeeds`, `\AsymLossTenSeeds`, …).
- Subspace smoothing (`\RsSub*`). Smoothing becomes a baseline in 6.8, no longer a contribution (Am1).
- The training-range clip, and every "sound for the real attacker" sentence.
- "Positive in every seed" and "N combined standard deviations".
- The word "cheap" (replaced by the runtime table).
- The draft's single temporal split and `numbers_temporal.tex` (replaced by the decay analysis, 3c).
- `numbers.tex` from the draft results: regenerated by `make_figures.py` from `results_family` + `results_family_s34`;
  macros of removed models are dropped.
