"""Tests for the group-ablation certificates (REVISION_PLAN 2a) and the partitions (2b).
Run:  python tests/test_certificate.py"""
import itertools, os, sys
from math import comb
import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.certify import ablation_certify, ablation_certify_exact, ceiling_r, votes_from_views


def brute(view_mal, y, subsets, attackable, r):
    """Certified iff, for every set A of r attackable groups and EVERY way the touched views can vote,
    correct votes > wrong votes (strict)."""
    out = []
    for v, t in zip(view_mal, y):
        ok = True
        for A in itertools.combinations(attackable, r):
            T = [i for i, s in enumerate(subsets) if set(s) & set(A)]
            for bits in itertools.product([0, 1], repeat=len(T)):
                w = v.copy()
                w[T] = bits
                c = int((w == t).sum())
                if not c > len(w) - c:
                    ok = False; break
            if not ok:
                break
        out.append(ok)
    return np.array(out)


def test_exact_matches_brute_force():
    rng = np.random.default_rng(0)
    for G, k, attackable in ((5, 1, [0, 1, 2, 3, 4]), (5, 2, [0, 1, 2, 3, 4]), (6, 2, [0, 2, 3, 5]), (5, 1, [1, 3])):
        subsets = list(itertools.combinations(range(G), k))
        N = 300
        y = rng.integers(0, 2, N)
        p = rng.uniform(0.5, 1.0, N)[:, None]                      # many samples near the boundary
        view_mal = np.where(rng.uniform(size=(N, len(subsets))) < p, y[:, None], 1 - y[:, None]).astype(bool)
        ex = ablation_certify_exact(torch.as_tensor(view_mal), torch.as_tensor(y), subsets, attackable, 3)
        for r in range(4):
            if r <= len(attackable):
                assert np.array_equal(ex[:, r], brute(view_mal.astype(int), y, subsets, attackable, r)), (G, k, r)


def test_exact_never_below_bound_and_is_monotone():
    rng = np.random.default_rng(1)
    G, k = 9, 1
    subsets = list(itertools.combinations(range(G), k))
    y = torch.as_tensor(rng.integers(0, 2, 2000))
    vm = torch.as_tensor(rng.uniform(size=(2000, len(subsets))) < 0.85) == y[:, None].bool()
    vm = torch.where(y[:, None].bool(), vm, ~vm)
    ex = ablation_certify_exact(vm, y, subsets, list(range(G)), 4)
    bd = ablation_certify(votes_from_views(vm), y, G, k, 4)
    assert not (bd & ~ex).any(), "exact certificate must contain the 2*Delta bound"
    assert not (ex[:, 1:] & ~ex[:, :-1]).any(), "certified at r implies certified at r-1"


def test_ceiling_table():
    assert [ceiling_r(9, k) for k in (1, 2, 3, 4, 5)] == [4, 2, 1, 1, 0]
    for G in range(2, 12):
        for k in range(1, G):
            r = ceiling_r(G, k)
            assert 2 * comb(G - r, k) > comb(G, k)
            assert r == G or 2 * comb(G - r - 1, k) <= comb(G, k)
    assert 2 * comb(9 - 2, 3) <= comb(9, 3)                          # k=3, r=2: 35 untouched vs 49 touched


def test_partitions_and_edit_footprints():
    """Every candidate partition tiles the features; in every in-scope edited file only attackable groups
    change, and never more groups than the r_needed stored in ps_results/grouping_footprint.csv."""
    import pandas as pd
    from malcert.partitions import PARTITIONS, partition, attackable, block_of_unit
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from grouping_footprint import footprints
    block_of_unit()
    fp = pd.read_csv(os.path.join(ROOT, "ps_results", "grouping_footprint.csv"))
    for p in PARTITIONS:
        gid, names = partition(p)
        assert gid.min() == 0 and set(gid) == set(range(len(names)))
        n, _, att = footprints(gid)                                  # asserts: only attackable groups change
        for e, v in n.items():
            assert v.max() == int(fp[(fp.partition == p) & (fp.edit == e)].r_needed.iloc[0]), (p, e)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("ok  ", t.__name__)
    print(f"all {len(tests)} certificate tests passed")
