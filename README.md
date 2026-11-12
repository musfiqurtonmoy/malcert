# Certified robustness of PE malware detectors (BODMAS, EMBER features)

Code for the paper *Certified Robustness of Machine-Learning Malware Detectors in Constrained
PE Feature Space: Group-Ablation Certificates and Constraint-Aware Certified Training*.

| Contribution | What it does | Code |
|---|---|---|
| C1 Threat model + attacks | FGSM / PGD inside the reachable feature region (immutable, monotone, domain), group-transplant attack | `malcert/data.py` (`threat_masks`), `malcert/attacks.py` |
| C2a Group-ablation certificate | Deterministic guarantee against arbitrary changes in up to *r* EMBER feature groups | `malcert/certify.py` (`ablation_*`), `AblationNet` in `models.py` |
| C2b Subspace smoothing | Gaussian randomized smoothing with noise only on mutable features | `malcert/certify.py` (`smooth_certify`) |
| C3 Certified training | IBP / CROWN-IBP over the constrained box, symmetric or malware-only (asymmetric) | `malcert/models.py` (`ibp`, `crown`, `input_box`), `malcert/train.py` |

## 1. Install (Windows or Linux, GTX 1050 Ti 4 GB)

```bash
conda create -n malcert python=3.11 -y
conda activate malcert
# GPU build that still supports Pascal (GTX 10xx). PyTorch 2.14 is the last release with CUDA 12.6 wheels.
pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cu126
pip install -r requirements.txt
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_arch_list())"   # expect True and sm_61 in the list
```
No GPU? `pip install torch --index-url https://download.pytorch.org/whl/cpu` works too; the quick preset runs on a CPU.

## 2. Get the data (once)

```bash
pip install gdown
gdown --folder "https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_" -O data
```
This downloads the official BODMAS files (`bodmas.npz` 261 MB, `bodmas_metadata.csv`, `bodmas_malware_category.csv`)
from https://whyisyoung.github.io/BODMAS/ . Cite Yang et al. (2021) when you use them.

## 3. Run

```bash
python run_all.py --preset quick      # 1 seed, ~40 min on CPU, ~10 min on the 1050 Ti
python run_all.py --preset full --out_dir results_full   # 3 seeds, paper budgets
python run_all.py --preset full --split temporal --out_dir results_temporal  # concept-drift check
python make_figures.py --res results_full --paper paper  # figures, LaTeX tables, numbers.tex
cd paper && latexmk -pdf main.tex
```

Outputs: `results*/results.json` (all numbers), `samples_seed*.npz` (per-sample certificates),
`figures/*.pdf|png`, `tables/*.tex`, and `tables/numbers.tex`, whose macros (`\MlpAcc`, `\AblOneCertR`, ...)
are what the manuscript prints. Re-running the experiments therefore updates every number in the paper.

## 4. Built-in sanity checks
* `violations` in the ablation results: test malware certified at *r* groups that the group-transplant
  attack still evaded. Must be 0 (a non-zero value means a bug).
* `violations` in certified training: malware certified at epsilon that PGD still evaded. Must be 0.

## 5. If something fails
* `CUDA out of memory` on 4 GB: lower `batch_size` in `malcert/config.py` or the `batch=` argument of `smooth_certify`.
* `no kernel image is available for execution on the device`: your PyTorch build lacks sm_61; reinstall with the cu126 command above.
