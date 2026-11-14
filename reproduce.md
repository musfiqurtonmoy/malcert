# Reproducing the paper

One command reruns every experiment and rebuilds every table, figure and number of the paper:

```
python reproduce.py
```

Every number in the manuscript is a LaTeX macro written by a script (`paper/tables/numbers_*.tex`), so a rerun
updates the paper without hand edits. `python reproduce.py --analysis-only` rebuilds all tables, figures and macros
from the results folders in the repository (about 1–2 minutes) without training anything.

## 1. Data

BODMAS (Yang et al., 2021): feature vectors, metadata and malware categories, into `data/`:

```
gdown --folder https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_ -O data
```

Expected files: `data/bodmas.npz`, `data/bodmas_metadata.csv`, `data/bodmas_malware_category.csv`.

## 2. Environments

| Environment | Used for | Definition |
|---|---|---|
| `malcert` (Python 3.11, PyTorch 2.14.0 cu126, LightGBM) | everything except feature extraction | `environment.yml`, exact versions in `requirements-lock.txt` |
| `malcert-ps` (Python 3.7, LIEF 0.10.1, EMBER extractor) | only `tools/ps_build.py` (problem-space measurement) | `environment-ps.yml`; EMBER at commit `d97a0b5`, installed with `--no-deps` |

```
conda env create -f environment.yml
conda activate malcert
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_arch_list())"
```

PyTorch must come from `https://download.pytorch.org/whl/cu126` on Pascal GPUs (sm_61); newer CUDA builds dropped them.
Set `GIT_EXE` to a git executable if git is not on `PATH`, so that each results file records whether the code had
uncommitted changes.

## 3. What `reproduce.py` runs

| Step | Command (run by the script) | Time on a GTX 1050 Ti |
|---|---|---|
| Unit tests | `tests/test_*.py` | a few minutes |
| Family split, seeds 0–2, all blocks | `run_all.py --preset full --split family --seeds 0,1,2 --out_dir results_family` | 1 h 20 min |
| Family split, seeds 3–4 | `run_all.py ... --seeds 3,4 --blocks clean,attacks,ablation,certified --out_dir results_family_s34` | 50 min |
| Random split, seeds 0–2 | `run_all.py --preset full --split random ... --out_dir results_random` | 50 min |
| Temporal cut-off 2019-12 | `run_all.py --preset full --split cutoff --cutoff 2019-12 ... --out_dir results_cut_2019-12` | 35 min |
| Temporal cut-off 2020-04 | `run_all.py --preset full --split cutoff --cutoff 2020-04 ... --out_dir results_cut_2020-04` | 45 min |
| Full-data check | `run_all.py ... --full_data --ablation_only_main --blocks clean,ablation --out_dir results_fulldata` | 15 min, 3.5 GB RAM |
| Uniform-ball ε sweep (40 models) | `tools/eps_sweep.py --seeds 0,1,2,3,4 --out results_eps_sweep` | 20–25 min |
| Analyses, tables, figures, macros | `tools/leakage_audit.py`, `representativeness.py`, `stats.py`, `temporal_decay.py`, `make_runtime.py`, `eps_sweep.py --analyse`, `problem_space.py --res`, `make_results.py`, `make_appendix.py` | 1–2 min |
| Overleaf archive | `paper_overleaf.zip` | seconds |

The exact arguments are in `RUNS` and `ANALYSIS` at the top of `reproduce.py`. Total: about 5.5 hours of training.

Training runs are **resumable**: if a run stops, rerun `python reproduce.py`; finished seeds and blocks are skipped.
A results folder accepts only results from the same code and configuration (`run_all.py` compares a SHA-256 of
`run_all.py` and `malcert/*.py`), so do not change the code between runs. Run one heavy job at a time on a machine
with 8 GB of RAM.

## 4. Optional steps (their outputs are in the repository)

* `--problem-space --ps-python <python of malcert-ps>`: copies 150 benign PE files from `C:\Windows\System32` and
  `C:\Windows\SysWOW64` into `ps_corpus/` (not versioned), applies the edits, extracts EMBER features, and rebuilds
  `ps_results/` (edit map, annotation evidence, edit families). Windows only; **no edited file is ever executed**.
  UPX 5.3.0 must be in `ps_tools/` for the out-of-scope packing edit.
* `--tuning`: reruns the grouping selection on the validation split and the grouped 3-fold cross-validation grids
  (about 75 minutes). The chosen settings are frozen in `malcert/config.py`; a rerun reproduces the grids, it does not
  change the configuration.

## 5. Outputs

* `results_*/results.json`: every metric, per seed, with provenance (git commit, code hash, package versions, device,
  command line) and the `violations` counts, which must all be 0.
* `results_*/samples_seed*.npz`: per-sample predictions and certificates, used by the analysis scripts.
* `paper/tables/*.tex`, `paper/figures/*.pdf`, `paper/tables/numbers_*.tex`: everything the manuscript includes.
* `paper_overleaf.zip`: the manuscript with all inputs, ready to upload to Overleaf.

The log of every decision, with the reviewer comment it answers, is `REVISION_LOG.md`.
