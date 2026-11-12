# Project: certified robustness of PE malware detectors (BODMAS)

Research code + manuscript for an Elsevier (Computers & Security) paper. Sole author: Md. Musfiqur Rahman.
The user is new to adversarial ML: explain the reason behind each step and each fix, briefly.

The paper is being revised before its first submission. `REVISION_PLAN.md` is the specification (work one stage
at a time, then stop and report); `REVISION_LOG.md` records every change with the reviewer comment it answers.
Git: branch `revision-1`; the reviewed draft is tag `draft-v1`; its numbers are in `results_draft_v1/`.

## Machine
Windows PC, 7.9 GB RAM, NVIDIA GTX 1050 Ti (4 GB, Pascal sm_61). C: is short on space: keep everything on D:.
- Env `malcert` (Python 3.11, `C:\Users\USER\miniconda3\envs\malcert`): all experiments.
  PyTorch must be `torch==2.14.0` from `https://download.pytorch.org/whl/cu126`: newer CUDA builds dropped Pascal.
  Check with `python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_arch_list())"` (needs sm_61).
- Env `malcert-ps` (Python 3.7, lief 0.10.1, EMBER extractor; `D:\malcert_envs\malcert-ps`): only for
  `tools/ps_build.py`. Activate it, or put its `Library\bin` on PATH, before calling its python.
- Git is not on PATH: `D:\malcert_envs\git\Library\cmd\git.exe`. Set `GIT_EXE` to it when starting runs, so
  provenance records uncommitted changes.
- Only 7.9 GB RAM: run one heavy job at a time (a GPU run, or anything that loads all of BODMAS).

## Layout
- `malcert/data.py`     BODMAS loading, 30K subset, feature units, natural bounds, threat model (C1)
- `malcert/attacks.py`  constrained FGSM/PGD, group-transplant attack (C1)
- `malcert/certify.py`  group-ablation certificate (C2a), randomized smoothing (C2b)
- `malcert/models.py`   MLP, AblationNet, IBP and CROWN bounds, constrained input box (C3)
- `malcert/train.py`    standard, Gaussian, PGD-AT, ablation, IBP, CROWN-IBP training
- `run_all.py`          all experiments -> `<out_dir>/results.json`, `samples_seed*.npz`, `log.txt`
- `make_figures.py`     figures, LaTeX tables and `paper/tables/numbers.tex` from results
- `tools/ps_build.py`   problem-space check, part 1 (`malcert-ps` env): corpus, edits E0-E9, EMBER features
- `tools/problem_space.py`  part 2 (`malcert` env): edit map, annotation evidence, coverage table, `numbers_ps.tex`
- `tools/eps_units.py`  epsilon in real units -> `numbers_eps.tex`
- `tools/eps_coverage.py --res <results>`  share of measured edits inside the box vs certified detection, per epsilon
- `tools/make_temporal.py`, `tools/compare.py`  temporal-vs-random tables; compare two results.json
- `ps_results/`         outputs of the problem-space check (versioned); `ps_corpus/`, `ps_tools/` are not versioned
- `paper/`              elsarticle manuscript; `results_text.tex` holds the Results section
- `tests/test_soundness.py`     IBP/CROWN bounds and the ablation vote count
- `tests/test_threat_model.py`  natural bounds, box, projection, every measured edit inside the threat set

## Commands
- Data (once): `gdown --folder https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_ -O data`
- Tests: `python tests/test_soundness.py` and `python tests/test_threat_model.py`
- Quick pilot (~8 min GPU): `python run_all.py --preset quick --out_dir results_pilot_<stage>`
- Full run (hours): `python run_all.py --preset full --out_dir <new folder>`
- Some blocks only: `--blocks clean,ablation,certified` (blocks: clean, attacks, ablation, smoothing, certified)
- Resume: re-run the same command; finished seeds and blocks are skipped. A folder whose results came from
  different code or configuration is refused: use a new `--out_dir`.
- Paper assets: `python make_figures.py --res <results folder> --paper paper`
- Problem-space check: `python tools/ps_build.py corpus|edit|extract` (env `malcert-ps`), then
  `python tools/problem_space.py` and `python tools/eps_units.py` (env `malcert`)

## Rules
- Long runs (full, temporal) exceed tool timeouts: start them in a separate terminal or in the background
  and poll `<out_dir>/log.txt`; never block on them.
- Run the quick preset as a pilot after every code change, into a new folder. Never start a long run without a
  passing pilot and passing tests.
- Never type an experimental number into the manuscript. Numbers come from macros in `paper/tables/numbers*.tex`;
  add a new macro in the script that owns the analysis if the text needs one.
- After a full run, re-read every sentence marked `%CHECK` in `paper/results_text.tex`, and rewrite any whose
  direction the new numbers contradict. Report negative results honestly.
- `violations` in results.json must be 0 for ablation and certified training. A non-zero value is a bug:
  stop and investigate before writing anything.
- Threat model. The annotation in `data.py` is frozen from measurements: `tools/problem_space.py` fails if it
  differs from what the evidence rule gives. Do not change it, the natural bounds or a certificate formula
  without explaining why the change keeps certificates sound, adding a test, and rerunning all tests.
  Never clip the box to the training-set range: that was the unsound part of draft v1.
- Problem-space check: benign files copied from `C:\Windows\System32` only; never execute an edited binary.
- Out of GPU memory: lower `batch_size` in `malcert/config.py`, or `batch` in `smooth_certify`.
- References in `paper/refs.bib` must be checked against Google Scholar before submission.
