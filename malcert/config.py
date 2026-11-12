"""Experiment configuration.

Two presets:
  quick : 1 seed, smaller certification budgets  -> runs on a laptop CPU in ~1 h
  full  : 3 seeds, paper-grade budgets          -> run on the GTX 1050 Ti for the final paper
"""
from dataclasses import dataclass, field, replace


@dataclass
class Config:
    # ---- data -------------------------------------------------------------
    data_npz: str = "data/bodmas.npz"
    meta_csv: str = "data/bodmas_metadata.csv"
    cat_csv: str = "data/bodmas_malware_category.csv"
    out_dir: str = "results"
    n_malware: int = 12773          # size of the 30K subset (abstract)
    n_benign: int = 17227
    split: str = "random"           # "random" (stratified 70/10/20) or "temporal"
    eval_split: str = "test"        # "val": evaluate on the validation split (pilots before Stage 3)
    seeds: tuple = (0, 1, 2)
    device: str = "auto"

    # ---- base network -----------------------------------------------------
    hidden: tuple = (512, 256)
    epochs: int = 30
    batch_size: int = 256
    lr: float = 1e-3
    weight_decay: float = 1e-5

    # ---- C1: attacks (budgets are in standardised feature units) ----------
    eps_list: tuple = (0.01, 0.02, 0.05, 0.1, 0.2, 0.5)
    pgd_steps: int = 50
    pgd_restarts: int = 1
    n_attack_points: int = 2000     # malware test samples attacked

    # ---- PGD adversarial training (empirical baseline) --------------------
    at_eps: float = 0.1
    at_steps: int = 10

    # ---- C2a: feature-group ablation certificates -------------------------
    # (name, partition, k). "main" was chosen on validation by the pre-registered rule (log 2-3, 2-5);
    # "second" is the declared coverage/accuracy operating point; "ember" is the negative baseline.
    ablation_configs: tuple = (("main", "aligned5", 2), ("second", "aligned7", 1), ("ember", "ember", 1))
    grouping: str = "aligned5"      # partition of the threat model's group attack (uniform attack table)
    lgbm_view_trees: int = 200      # LightGBM per view (2c), fixed
    giri_sigma: float = 0.3         # Giri et al. (2026) re-implementation: their sigma (Sec. 4.2, 4.3)
    giri_drop: float = 0.2          # share of groups removed per sample (their Sec. 3)
    group_attack_points: int = 500
    group_attack_donors: int = 10
    group_attack_max_r: int = 3

    # ---- C2b: Gaussian randomized smoothing --------------------------------
    sigmas: tuple = (0.25, 0.5, 1.0)
    n0: int = 100
    n_cert: int = 10000
    alpha: float = 0.001
    n_cert_points: int = 1000

    # ---- C3: certified training (IBP / CROWN-IBP) -------------------------
    ibp_hidden: tuple = (256, 256)
    ibp_train_eps: float = 0.05
    ibp_epochs: int = 40
    ibp_warmup: int = 5             # clean epochs before the eps ramp
    ibp_ramp: int = 20              # epochs to ramp eps from 0 -> target
    cert_eps_list: tuple = (0.005, 0.01, 0.02, 0.05, 0.1)


def get_config(preset: str = "quick", **overrides) -> Config:
    cfg = Config()
    if preset == "quick":
        cfg = replace(cfg, seeds=(0,), epochs=15, n_cert=2000, n_cert_points=500,
                      n_attack_points=1000, pgd_steps=30, ibp_epochs=30,
                      ibp_ramp=15, group_attack_points=300, group_attack_donors=5)
    elif preset != "full":
        raise ValueError(preset)
    return replace(cfg, **overrides)
