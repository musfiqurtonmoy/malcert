"""Tests for the threat model (C1) after the Stage-1 repair.  Run:  python tests/test_threat_model.py

What they protect:
  * the feature units tile the vector and never straddle two groups;
  * the natural bounds really hold on BODMAS, so intersecting a box with them is sound;
  * the box is no longer clipped to the training-set range;
  * attack projection and certificate box describe the same set;
  * EVERY in-scope edited file of the problem-space check lies inside the threat set:
    its changed groups are attackable (group certificate), and its vector is inside the constrained
    box at the epsilon the edit needs (L-infinity certificates);
  * the annotation frozen in data.py is exactly what the evidence rule gives.
The last two need ps_results/ (tools/ps_build.py, then tools/problem_space.py).
"""
import os, sys
import numpy as np
import pandas as pd
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.attacks import Constraints
from malcert.config import get_config
from malcert.data import (EDIT_SCOPE, FEATURE_UNITS, GROUP_NAMES, N_FEAT, Preprocessor, attackable_groups, group_ids,
                          load_subset, natural_bounds, split_indices, threat_masks, unit_index)
from malcert.models import input_box

RES = os.path.join(ROOT, "ps_results")


def test_units_tile_the_vector_and_respect_groups():
    gid = group_ids()
    assert FEATURE_UNITS[0][1] == 0 and FEATURE_UNITS[-1][2] == N_FEAT
    for (n, a, b, kind), nxt in zip(FEATURE_UNITS, FEATURE_UNITS[1:] + [None]):
        assert a < b and kind in ("hist", "count", "flag", "value", "hashed"), n
        assert len(set(gid[a:b])) == 1, f"unit {n} straddles two groups"
        assert nxt is None or nxt[1] == b
    assert len({u[0] for u in FEATURE_UNITS}) == len(FEATURE_UNITS)


def test_annotation_is_well_formed():
    mutable, monotone = threat_masks()
    assert not (monotone & ~mutable).any(), "a monotone feature must be mutable"
    lo, hi = natural_bounds()
    for n, (a, b, kind, _) in unit_index().items():
        assert len(set(mutable[a:b])) == 1 and len(set(monotone[a:b])) == 1, f"unit {n} is split"
        if monotone[a]:
            assert kind == "count", f"{n}: only counts and sizes may be increase-only"
        if kind == "hashed":
            assert np.isinf(lo[a:b]).all() and np.isinf(hi[a:b]).all(), f"{n}: hashed features have no bound"
    att = attackable_groups()
    gid = group_ids()
    assert all(mutable[gid == g].any() for g in att) and not any(mutable[gid == g].any() for g in range(9) if g not in att)


def _bodmas(seed=0):
    os.chdir(ROOT)
    cfg = get_config("quick")
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=seed)
    return data, sp, Preprocessor().fit(data["X"][sp["tr"]])


def test_natural_bounds_hold_on_bodmas():
    """Every row of the 30K subset (train, val and test) satisfies the natural bounds, in raw and in
    standardised space. If this failed, the box could cut off points that real files occupy."""
    data, sp, pp = _bodmas()
    lo, hi = natural_bounds()
    X = data["X"]
    assert (X >= lo).all() and (X <= hi).all()
    zlo, zhi = pp.bounds()
    Z = pp.transform(X)
    assert (Z >= zlo - 1e-4).all() and (Z <= zhi + 1e-4).all()
    assert np.isfinite(zlo).sum() == np.isfinite(lo).sum() and np.isfinite(zhi).sum() == np.isfinite(hi).sum()


def test_box_is_not_clipped_to_training_range():
    """Draft v1 clipped the box to [training min, training max]. A sample at the training maximum of an
    unbounded mutable feature must now be allowed to move up by the full epsilon."""
    data, sp, pp = _bodmas()
    mutable, monotone = threat_masks()
    zlo, zhi = (torch.as_tensor(v) for v in pp.bounds())
    Ztr = torch.as_tensor(pp.transform(data["X"][sp["tr"]]))
    free = np.where(mutable & ~np.isfinite(pp.bounds()[1]))[0]          # mutable, no natural upper bound
    assert len(free) > 0
    j = int(free[0])
    x = Ztr[Ztr[:, j].argmax()][None]                                   # the training maximum of feature j
    lo, hi = input_box(x, 0.5, torch.as_tensor(mutable), torch.as_tensor(monotone), zlo, zhi)
    assert torch.isclose(hi[0, j], x[0, j] + 0.5), "box is still clipped at the training maximum"
    assert torch.all(lo <= x) and torch.all(x <= hi)
    assert torch.all(lo[:, ~torch.as_tensor(mutable)] == x[:, ~torch.as_tensor(mutable)])
    bounded = torch.isfinite(zlo)
    assert torch.all(lo[:, bounded] >= torch.minimum(zlo, x[0])[bounded] - 1e-6)


def test_projection_and_box_agree():
    """Constraints.project (used by the attacks) maps every point into input_box (used by the certificates),
    and leaves points of the box unchanged. Otherwise attack and certificate would use different sets."""
    data, sp, pp = _bodmas()
    mutable, monotone = threat_masks()
    zlo, zhi = pp.bounds()
    C = Constraints(mutable, monotone, zlo, zhi, "cpu", constrained=True)
    x = torch.as_tensor(pp.transform(data["X"][sp["te"]][:256]))
    g = torch.Generator().manual_seed(0)
    for eps in (0.01, 0.1, 1.0):
        lo, hi = input_box(x, eps, C.mask, C.mono, C.zlo, C.zhi)
        p = C.project(x, x + 3 * eps * torch.randn(x.shape, generator=g), eps)
        assert torch.all(p >= lo - 1e-6) and torch.all(p <= hi + 1e-6)
        inside = lo + (hi - lo) * torch.rand(x.shape, generator=g)
        assert torch.allclose(C.project(x, inside, eps), inside, atol=1e-6)


def _edits():
    f = os.path.join(RES, "features.npz")
    assert os.path.exists(f), "ps_results/features.npz is missing: run tools/ps_build.py (corpus, edit, extract)"
    F = np.load(f)
    st = np.load(os.path.join(RES, "bodmas_train_stats_seed0.npz"))
    pp = Preprocessor(); pp.mu, pp.sd = st["mu"], st["sd"]
    X, file, edit = F["X"], F["fname"], F["edit"]
    orig = {n: X[i] for i, n in enumerate(file) if edit[i] == "orig"}
    return pp, X, file, edit, F["variant"], orig


def test_every_in_scope_edit_is_inside_the_threat_set():
    pp, X, file, edit, variant, orig = _edits()
    mutable, monotone = threat_masks()
    gid, att = group_ids(), set(attackable_groups())
    zlo, zhi = (torch.as_tensor(v) for v in pp.bounds())
    mask, mono = torch.as_tensor(mutable), torch.as_tensor(monotone)
    n = 0
    for i in range(len(X)):
        if EDIT_SCOPE.get(str(edit[i])) != "in":
            continue
        n += 1
        tag = f"{file[i]} {edit[i]}/{variant[i]}"
        o, e = orig[str(file[i])], X[i]
        changed = e != o
        # (a) group threat: only attackable groups change
        assert set(gid[changed]) <= att, f"{tag}: changes a group that is not attackable"
        # (b) constrained box at the epsilon the edit needs, computed as run_all.py computes it
        zo, ze = (torch.as_tensor(pp.transform(v[None])) for v in (o, e))
        eps = float((ze - zo).abs().max())
        lo, hi = input_box(zo, eps, mask, mono, zlo, zhi)
        bad = torch.where((ze < lo - 1e-5) | (ze > hi + 1e-5))[1].tolist()
        assert not bad, f"{tag}: outside the box at eps={eps:.3g} in features {bad[:5]}"
    assert n > 1000, f"only {n} in-scope edited files found"


def test_frozen_annotation_equals_evidence_rule():
    ev = pd.read_csv(os.path.join(RES, "unit_evidence.csv"))
    mutable, monotone = threat_masks()
    idx = unit_index()
    assert set(ev.unit) == set(idx)
    for r in ev.itertuples():
        a = idx[r.unit][0]
        frozen = "monotone" if monotone[a] else ("mutable" if mutable[a] else "immutable")
        assert frozen == r.rule_gives, f"{r.unit}: data.py says {frozen}, the evidence rule gives {r.rule_gives}"


def test_inplace_standardisation_matches_fit_transform():
    """Preprocessor.fit_transform_inplace (memory-lean path for full-data runs) is checked against an exact
    float64 computation, and must be at least as accurate as fit + transform, which accumulates in float32
    (its sd is off by up to ~2e-4 relative on features with tiny spread)."""
    data, sp, pp = _bodmas()
    Z = np.sign(data["X"].astype(np.float64)) * np.log1p(np.abs(data["X"].astype(np.float64)))
    mu, sd = Z[sp["tr"]].mean(0), Z[sp["tr"]].std(0)
    sd[sd < 1e-6] = 1.0
    ref = (Z - mu) / sd
    X = np.ascontiguousarray(data["X"].astype(np.float32))
    p2 = Preprocessor()
    p2.fit_transform_inplace(X, sp["tr"])                 # returns X; the statistics are kept on p2
    err_new, err_old = np.abs(p2.sd - sd) / sd, np.abs(pp.sd - sd) / sd
    assert err_new.max() < 1e-5 and err_new.max() <= err_old.max()
    assert np.abs(p2.mu - mu).max() < 1e-4
    assert np.abs(X - ref).max() < 1e-3


def test_run_all_block_bookkeeping():
    import run_all
    assert run_all.done_blocks({}) == []
    assert run_all.done_blocks({"lightgbm": 1, "lightgbm_mono": 1, "mlp": 1, "smoothing": {}}) == ["clean", "smoothing"]
    assert run_all.done_blocks({"lightgbm": 1}) == []                      # a half-written block is not done
    seeds = {run_all.block_seed(s, b) for s in range(50) for b in run_all.BLOCKS}
    assert len(seeds) == 50 * len(run_all.BLOCKS)                          # no two (seed, block) share a stream
    assert run_all.block_seed(0, "clean") == 0                             # seed 0 'clean' = draft-v1 stream
    c = run_all.git_commit()
    assert c is None or (len(c) == 40 and all(ch in "0123456789abcdef" for ch in c))


def test_run_all_resume_config_check():
    """REVISION_LOG 3-10: nested tuples (ablation_configs, lgbm_view_params) made every resume fail."""
    import json
    import run_all
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    kw = dict(out_dir="x", split="family", eval_split="test", cutoff="2019-12", full_data=False, ablation_only_main=False,
              data_npz=os.path.join("data", "bodmas.npz"), meta_csv=os.path.join("data", "bodmas_metadata.csv"),
              cat_csv=os.path.join("data", "bodmas_malware_category.csv"))
    cfg = get_config("full", **kw)
    live = run_all.config_json(cfg)
    assert any(isinstance(v, list) and v and isinstance(v[0], list) for v in live.values())   # nested values exist
    stored = json.loads(json.dumps(live))                                                       # as written to disk
    assert run_all.config_diff(stored, live) == []                                              # same run resumes
    assert run_all.config_diff(stored, run_all.config_json(get_config("full", **dict(kw, seeds=(3, 4), out_dir="y")))) == []
    assert run_all.config_diff(stored, run_all.config_json(get_config("full", **dict(kw, split="random")))) == ["split"]
    old = {k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(cfg).items()}          # the buggy comparison
    assert any(stored[k] != old[k] for k in old)                                                # ... which did fail
    res = os.path.join(root, "results_family", "results.json")                                  # the real Stage 3 folder
    if os.path.exists(res):
        assert run_all.config_diff(json.load(open(res))["config"], live) == []


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"all {len(tests)} threat-model tests passed")
