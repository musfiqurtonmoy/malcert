"""Tests for the family-disjoint split and the grouped CV folds (REVISION_PLAN 3b, 2i).  Run:  python tests/test_split.py"""
import os, sys
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.data import family_folds, family_split


def _data():
    from malcert.config import get_config
    from malcert.data import select_subset
    os.chdir(ROOT)
    sel, y, meta = select_subset(get_config("quick"), 0)
    return y[sel], meta["family"].fillna("benign").values[sel], meta["category"].values[sel]


def _mix(y, cat, idx):
    m = idx[y[idx] == 1]
    c, n = np.unique(cat[m], return_counts=True)
    return dict(zip(c, n / n.sum()))


def _disjoint(fam, y, parts):
    sets = [set(fam[p][y[p] == 1]) for p in parts]
    return all(not (sets[i] & sets[j]) for i in range(len(sets)) for j in range(i + 1, len(sets)))


def test_family_split_properties():
    y, fam, cat = _data()
    mal = y == 1
    whole = _mix(y, cat, np.arange(len(y)))
    tests = []
    for seed in range(3):
        sp = family_split(y, fam, cat, seed)
        allidx = np.concatenate([sp["tr"], sp["va"], sp["te"]])
        assert len(allidx) == len(y) and len(np.unique(allidx)) == len(y), "every sample in exactly one part"
        assert _disjoint(fam, y, [sp["tr"], sp["va"], sp["te"]])
        for k, share in zip(("tr", "va", "te"), (0.7, 0.1, 0.2)):
            m, b = int(mal[sp[k]].sum()), int((~mal)[sp[k]].sum())
            assert m > 0 and b > 0
            assert abs(m / mal.sum() - share) < 0.035, (seed, k, m / mal.sum())
            assert abs(b / (~mal).sum() - share) < 0.01
            mix = _mix(y, cat, sp[k])
            for c in ("trojan", "worm", "backdoor"):              # the three large categories stay close
                assert abs(mix.get(c, 0) - whole[c]) < 0.13, (seed, k, c, mix.get(c, 0), whole[c])   # whole families: ~10 pts
        assert all(np.array_equal(sp[k], family_split(y, fam, cat, seed)[k]) for k in sp)
        tests.append(set(sp["te"].tolist()))
    assert tests[0] != tests[1], "different seeds give different splits"


def test_folds_properties():
    y, fam, cat = _data()
    sp = family_split(y, fam, cat, 0)
    pool = np.concatenate([sp["tr"], sp["va"]])
    folds = family_folds(y, fam, cat, pool, 3, 0)
    allidx = np.concatenate(folds)
    assert sorted(allidx.tolist()) == sorted(pool.tolist()), "folds partition train + val exactly"
    assert not (set(allidx.tolist()) & set(sp["te"].tolist())), "test part never in a fold"
    assert _disjoint(fam, y, folds)
    whole = _mix(y, cat, pool)
    for f in folds:
        assert abs((y[f] == 1).sum() / (y[pool] == 1).sum() - 1 / 3) < 0.035
        mix = _mix(y, cat, f)
        for c in ("trojan", "worm", "backdoor"):
            assert abs(mix.get(c, 0) - whole[c]) < 0.13, (c, mix.get(c, 0), whole[c])


def test_singleton_malware_without_family():
    y = np.array([1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    fam = np.array(["a", "a", "benign"] + ["benign"] * 7, dtype=object)
    cat = np.array(["trojan", "trojan", "worm"] + ["benign"] * 7, dtype=object)
    sp = family_split(y, fam, cat, 0)
    assert sorted(np.concatenate(list(sp.values())).tolist()) == list(range(10))
    part = {i: k for k, v in sp.items() for i in v}
    assert part[0] == part[1], "family a stays together"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("ok  ", t.__name__)
    print(f"all {len(tests)} split tests passed")
