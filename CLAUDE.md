# Project: certified robustness of PE malware detectors (BODMAS)

Research code + manuscript for an Elsevier (Computers & Security) paper by Ababil Hossain Fahad.
The user is new to adversarial ML: explain the reason behind each step and each fix, briefly.

## Machine
Windows PC, NVIDIA GTX 1050 Ti (4 GB, Pascal sm_61). Conda env `malcert`, Python 3.11.
PyTorch must be `torch==2.14.0` from `https://download.pytorch.org/whl/cu126`: newer CUDA builds dropped Pascal.
Check with `python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_arch_list())"` (needs sm_61).

## Layout
- `malcert/data.py`     BODMAS loading, 30K stratified subset, EMBER feature groups, threat masks (C1)
- `malcert/attacks.py`  constrained FGSM/PGD, group-transplant attack (C1)
- `malcert/certify.py`  group-ablation certificate (C2a), randomized smoothing (C2b)
- `malcert/models.py`   MLP, AblationNet, IBP and CROWN bounds, constrained input box (C3)
- `malcert/train.py`    standard, Gaussian, PGD-AT, ablation, IBP, CROWN-IBP training
- `run_all.py`          all experiments -> `<out_dir>/results.json`, `samples_seed*.npz`, `log.txt`
- `make_figures.py`     figures, LaTeX tables and `paper/tables/numbers.tex` from results
- `paper/`              elsarticle manuscript; `results_text.tex` holds the Results section
- `tests/test_soundness.py`  checks IBP/CROWN bounds and the ablation vote count

## Commands
- Data (once): `gdown --folder https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_ -O data`
- Tests: `python tests/test_soundness.py`
- Quick run (~10 min GPU): `python run_all.py --preset quick --out_dir results`
- Full run (hours): `python run_all.py --preset full --out_dir results_full`
- Paper assets: `python make_figures.py --res results_full --paper paper`

## Rules
- Long runs (full, temporal) exceed tool timeouts: start them in a separate terminal or in the background
  and poll `results_full/log.txt`; never block on them.
- Never type an experimental number into the manuscript. Numbers come from `paper/tables/numbers.tex`
  macros; add a new macro in `make_figures.py` if the text needs one.
- After a full run, re-read every sentence marked `%CHECK` in `paper/results_text.tex`, and rewrite any whose
  direction the new numbers contradict. Report negative results honestly.
- `violations` in results.json must be 0 for ablation and certified training. A non-zero value is a bug:
  stop and investigate before writing anything.
- Do not change the threat model (`threat_masks` in data.py) or certificate formulas without explaining why
  the change keeps certificates sound; rerun the tests afterwards.
- Out of GPU memory: lower `batch_size` in `malcert/config.py`, or `batch` in `smooth_certify`.
- References in `paper/refs.bib` must be checked against Google Scholar before submission.
