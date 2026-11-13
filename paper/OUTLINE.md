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
- Cost of certification: "\CmpFAbs{} points, not significant" with its interval
  [\CmpFLo, \CmpFHi], Holm p = \CmpFP. **(new)** `\CmpFAbs` (absolute value of `\CmpFDiff`) in `stats.py`.
- Box-constrained CROWN-IBP is reported as a **negative ablation**: +\CmpBDiff{} points [\CmpBLo, \CmpBHi], p = \CmpBP.
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
   - Clean accuracy 92.8% against 94.6%: 1.8 points, not significant [−4.2, 0.6], p = 0.20.
   - Answers A2, A3, B5.
3. **Edit-aware certified training.**
   - Threat sets T_f(t) built from the measured edit families. Certified over T_f(1): 56.0% [49.0, 63.0], against
     0.0% for uniform-ball and box-constrained CROWN-IBP (+56.0 [49.0, 62.9], Holm p = 0.0001). C3 rule met.
   - Box-constrained training is no better than uniform-ball training at ε = 0.05 (negative ablation).
   - Answers A2, A3.
4. **Evaluation that does not overstate** (answers A5, B4, B6, B7). Family-disjoint split, 5 seeds, paired intervals,
   Holm correction across 6 pre-registered comparisons, and a temporal decay analysis.
   - Random splits overstate certified detection by 14–50 points (per-view LightGBM 96.6% vs 55.1%).
   - Certified detection falls below 90% of its first-month value within 1–6 months. Retraining recovers 8–16 points.

## Abstract draft (≈ 230 words; all numbers are macros)

Machine-learning malware detectors can be evaded by small edits to a PE file. Certified defences promise
guarantees, but only for a threat model that matches what an attacker can actually change. We measure that.
\PsNFilesAll{} benign PE files are modified with \PsNEditTypesInScope{} functionality-preserving edit types. The
resulting \PsNEditedInScopeAll{} feature vectors define a threat model that contains every one of them; the
draft-style threat model contained only \PsDraftBoxInsidePct\%. The measurements show that no edit touches a single
EMBER feature group and that an L-infinity ball of the radius used in certified training covers only
\PsEpsLeTrainPct\% of the edits. We therefore align the groups of a group-ablation certificate with the measured
edits, and train networks against threat sets shaped like the measured edit families. On a family-disjoint split of
BODMAS (\NSeedsFam{} seeds, 95\% intervals), a per-view LightGBM detector certifies \FamCertLgbmViews\% of test
malware against any edit confined to one edit-aligned group. Its clean accuracy is \CmpFAbs{} points below
LightGBM, not significant. Under a group-transplant attack it still detects \FamGattackLgbmViews\%, while LightGBM
detects \FamGattackLgbm\%. Edit-aware certified training certifies \FamCertEdit\% of malware over the
measured edit families, against \FamCertUnc\% for uniform-ball training (paired difference
\CmpADiff{} points, [\CmpALo, \CmpAHi]). Restricting training to the per-feature box gives no gain. Random train/test
splits overstate certified robustness by up to \RandFamGapMax{} points compared with family-disjoint testing.
Certified detection decays within months of the training cut-off, and retraining recovers \TdRetrainGainMin--\TdRetrainGainMax{}
points.

**(new) macros:**
- `stats.py`: `\NSeedsFam`, `\FamCertLgbmViews` (with `Lo`/`Hi`), `\FamGattackLgbmViews`, `\FamGattackLgbm`,
  `\FamCertEdit`, `\FamCertUnc`, `\CmpFAbs`, `\RandFamGapMin` / `\RandFamGapMax` (over certified-detection metrics),
  and family/random means and intervals for every model in the summary.
- `problem_space.py`: `\PsNFilesAll`, `\PsNEditedInScopeAll` (PE32+ and PE32 together).
- `temporal_decay.py` → `numbers_decay.tex`: first-month values, months to 90%, `\TdRetrainGainMin` / `\TdRetrainGainMax`.

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
