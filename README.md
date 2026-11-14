# Certified robustness of PE malware detectors against measured edits

Code, results and manuscript for the paper

> Md. Musfiqur Rahman. *Certified Robustness of Machine-Learning Malware Detectors in Constrained PE Feature Space:
> Group-Ablation Certificates and Constraint-Aware Certified Training.* 2026.

The repository measures which EMBER features real, functionality-preserving edits to Windows PE files change, builds a
threat model from those measurements, and evaluates three kinds of certified defence on BODMAS:

| Part | What it does | Code |
|---|---|---|
| Problem-space measurement | 9 in-scope edit types (plus packing, out of scope) applied to 150 benign PE files; EMBER features; edit map and coverage | `tools/ps_build.py`, `tools/problem_space.py`, results in `ps_results/` |
| Threat model | feature annotation (immutable / mutable / increase-only), natural bounds, constrained box, group threat | `malcert/data.py`, `malcert/attacks.py` |
| Group-ablation certificates | exact worst-case certificate and ceiling, edit-aligned groupings, MLP or LightGBM per view | `malcert/certify.py`, `malcert/partitions.py`, `run_all.py` |
| Certified training | CROWN-IBP on the uniform ball, the constrained box and the measured edit families (edit-aware) | `malcert/models.py`, `malcert/train.py`, `tools/edit_families.py` |
| Evaluation | family-disjoint and temporal splits, 5 seeds, pre-registered comparisons, baselines (monotonic LightGBM, PGD-AT, randomized smoothing, a re-implementation of Giri et al.) | `run_all.py`, `tools/stats.py`, `tools/temporal_decay.py` |

No malware is handled by the measurement code, and no edited file is ever executed.

## 1. Install

Tested on Windows 10 with an NVIDIA GTX 1050 Ti (4 GB) and 8 GB of RAM.

```bash
conda env create -f environment.yml          # environment "malcert": Python 3.11, PyTorch 2.14.0 (cu126), LightGBM
conda activate malcert
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_arch_list())"
```

Exact package versions are in `requirements-lock.txt`. PyTorch 2.14.0 from the cu126 index is the last build that
supports Pascal GPUs (sm_61). Only the optional problem-space measurement needs a second environment,
`environment-ps.yml` (Python 3.7, LIEF 0.10.1 and the EMBER feature extractor, which is installed separately under its
own licence and not included here).

## 2. Data

BODMAS (Yang et al., 2021) is not included. Download it once into `data/`:

```bash
pip install gdown
gdown --folder "https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_" -O data
```

This gives `data/bodmas.npz`, `data/bodmas_metadata.csv` and `data/bodmas_malware_category.csv` (about 280 MB).
Please cite the BODMAS paper when you use them.

## 3. Reproduce every table and figure

```bash
python reproduce.py                  # unit tests, all experiments (~5.5 h on a GTX 1050 Ti), all tables and figures
python reproduce.py --analysis-only  # rebuild tables, figures and macros from the results in this repository (~2 min)
```

Every number in the manuscript is a LaTeX macro written by a script (`paper/tables/numbers_*.tex`), so the paper
updates without hand edits. Training runs are resumable. `reproduce.md` lists every step, its exact command and its run
time, and the optional steps (`--problem-space`, `--tuning`).

## 4. Which results feed which part of the paper

| Results folder | Produced by | Feeds |
|---|---|---|
| `ps_results/` | `tools/ps_build.py`, `problem_space.py`, `eps_units.py`, `edit_families.py`, `extractor_check.py` | §3: edit map, annotation, ε in real units, coverage table, edit families; App. C, D |
| `results_family/`, `results_family_s34/` | `run_all.py --split family`, seeds 0–2 and 3–4 | §6.1–6.5: main, attack, group-certificate, certified-training and comparison tables; per-category and ε-coverage figures; runtime table; App. F per-seed table |
| `results_family/` (smoothing block, seeds 0–2) | `run_all.py` | §6.8: smoothing table |
| `results_random/` | `run_all.py --split random` | §6.6: random vs family table |
| `results_fulldata/` | `run_all.py --full_data` | §6.6: full-data check |
| `results_cut_2019-12/`, `results_cut_2020-04/` | `run_all.py --split cutoff` | via `results_temporal_decay/` (`tools/temporal_decay.py`): §6.7 temporal table and decay figure |
| `results_eps_sweep/` | `tools/eps_sweep.py` | §6.4: ε-sweep figure, sweep row of the certified-training table |
| `results_leakage/` | `tools/leakage_audit.py` | §5: leakage audit |
| `results_repr/` | `tools/representativeness.py` | §5: representativeness table |
| `results_grouping_val/` | `tools/grouping_select.py` | App. E: grouping candidates |
| `results_tuning/` | `tools/tune_validation.py` | App. F: tuning grids (settings frozen in `malcert/config.py`) |
| `checks/` | `tools/mem_dry_run.py` | memory check behind the 30,000-file subset |

Tables and figures are written by `tools/make_results.py` (§6), `tools/make_appendix.py` (appendices),
`tools/stats.py`, `tools/make_runtime.py` and `tools/problem_space.py`. Every `results*/results.json` records its
provenance (commit, code hash, package versions, device, command) and `violations` counts, which are all 0.

## 5. Tests

```bash
python tests/test_soundness.py      # IBP / CROWN bounds and the ablation vote count
python tests/test_certificate.py    # exact certificate, ceiling, partitions
python tests/test_threat_model.py   # natural bounds, box, projection, every measured edit inside the threat set
python tests/test_split.py          # family-disjoint split and grouped folds
python tests/test_families.py       # edit-family sets and edit-aware certification
```

## 6. Development history

`REVISION_LOG.md` records every change made while revising the draft, with the reviewer comment it answers and the
basis of every choice; `REVISION_PLAN.md` is the plan it followed. Earlier results folders and pilot runs remain in the
git history.

## 7. Citation

```bibtex
@unpublished{rahman2026certified,
  author = {Rahman, Md. Musfiqur},
  title  = {Certified Robustness of Machine-Learning Malware Detectors in Constrained {PE} Feature Space:
            Group-Ablation Certificates and Constraint-Aware Certified Training},
  note   = {Manuscript},
  year   = {2026},
  url    = {https://github.com/musfiqurtonmoy/malcert}
}
```

Code: MIT licence (`LICENSE`). BODMAS and the EMBER extractor are third-party and keep their own terms.
