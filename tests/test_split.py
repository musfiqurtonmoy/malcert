"""Tests for the family-disjoint split (REVISION_PLAN 3b, split function only).  Run:  python tests/test_split.py"""
import os, sys
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.data import family_split


def _data():
    from malcert.config import get_config
    from malcert.data import select_subset
    os.chdir(ROOT)
    sel, y, meta = select_subset(get_config("quick"), 0)
    return y[sel], meta["family"].fillna("benign").values[sel]


def test_family_split_properties():
    y, fam = _data()
    mal = y == 1
    splits = []
    for seed in range(3):
        sp = family_split(y, fam, seed)
        allidx = np.concatenate([sp["tr"], sp["va"], sp["te"]])
        assert len(allidx) == len(y) and len(np.unique(allidx)) == len(y), "every sample in exactly one part"
        fams = {k: set(fam[sp[k]][y[sp[k]] == 1]) for k in sp}
        assert not (fams["tr"] & fams["va"]) and not (fams["tr"] & fams["te"]) and not (fams["va"] & fams["te"])
        for k, share in zip(("tr", "va", "te"), (0.7, 0.1, 0.2)):
            m = int(mal[sp[k]].sum()); b = int((~mal)[sp[k]].sum())
            assert m > 0 and b > 0, "both classes in every part"
            assert abs(m / mal.sum() - share) < 0.03, (seed, k, m / mal.sum())
            assert abs(b / (~mal).sum() - share) < 0.01
        assert all(np.array_equal(sp[k], family_split(y, fam, seed)[k]) for k in sp), "deterministic per seed"
        splits.append(set(sp["te"].tolist()))
    assert splits[0] != splits[1], "different seeds give different splits"


def test_singleton_malware_without_family():
    y = np.array([1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    fam = np.array(["a", "a", "benign", "benign", "benign", "benign", "benign", "benign", "benign", "benign"], dtype=object)
    sp = family_split(y, fam, 0)
    assert sorted(np.concatenate(list(sp.values())).tolist()) == list(range(10))
    part = {i: k for k, v in sp.items() for i in v}
    assert part[0] == part[1], "family a stays together"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("ok  ", t.__name__)
    print(f"all {len(tests)} split tests passed")
