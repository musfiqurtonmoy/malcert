"""Tests for edit-family threat sets and edit-aware certification (REVISION_PLAN 2h).
Run:  python tests/test_families.py   (needs ps_results/ from tools/ps_build.py, problem_space.py, edit_families.py)"""
import os, sys
import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.data import FAMILIES, Preprocessor, slog1p_
from malcert.models import MLP, family_box, load_families, ibp, crown

RES = os.path.join(ROOT, "ps_results")
SCALES = (0.25, 0.5, 1.0, 2.0)


def _setup():
    st = np.load(os.path.join(RES, "bodmas_train_stats_seed0.npz"))
    pp = Preprocessor(); pp.mu, pp.sd = st["mu"], st["sd"]
    zlo, zhi = (torch.as_tensor(v) for v in pp.bounds())
    fams = load_families(pp.sd, "cpu")
    E = np.load(os.path.join(RES, "edit_families.npz"))
    F = np.load(os.path.join(RES, "features.npz"))
    halves = dict(np.loadtxt(os.path.join(RES, "corpus_halves.csv"), delimiter=",", dtype=str, skiprows=1))
    return pp, zlo, zhi, fams, E, F, halves


def test_box_shape():
    pp, zlo, zhi, fams, E, F, _ = _setup()
    X = torch.as_tensor(pp.transform(F["X"][F["edit"] == "orig"]))
    for f, (lo_z, hi_z) in fams.items():
        sup = torch.as_tensor(E[f + "_support"])
        assert torch.all(lo_z <= 0) and torch.all(hi_z >= 0)
        assert torch.all(lo_z[~sup] == 0) and torch.all(hi_z[~sup] == 0)
        for t in SCALES:
            lo, hi = family_box(X, t, lo_z, hi_z, zlo, zhi)
            assert torch.all(lo <= X) and torch.all(X <= hi)
            assert torch.all(lo[:, ~sup] == X[:, ~sup]) and torch.all(hi[:, ~sup] == X[:, ~sup])
            b = torch.isfinite(zlo)
            assert torch.all(lo[:, b] >= torch.minimum(zlo, X)[:, b] - 1e-6)


def test_edits_inside_sets_and_certificates_consistent():
    """Every eval-half edited vector counted inside T_f(t) lies inside family_box(original, t); and for a random
    network, a certified original (label = its own prediction) is never flipped by its real edit."""
    pp, zlo, zhi, fams, E, F, halves = _setup()
    torch.manual_seed(0)
    net = MLP(F["X"].shape[1], (64, 32)).eval()
    # Shrink the first-layer weights on the features any family can change: margins then come mostly from fixed
    # features, so many samples certify, while the edited features still move the output a little (non-trivial).
    sup_any = torch.as_tensor(np.any([E[f + "_support"] for f in FAMILIES], 0))
    with torch.no_grad():
        net.linears[0].weight[:, sup_any] *= 1e-3
    X, fn, ed = F["X"], F["fname"], F["edit"]
    orig = {f: X[i] for i, f in enumerate(fn) if ed[i] == "orig"}
    n_in = n_cert = 0
    for f, edits in FAMILIES.items():
        rows = [i for i in range(len(X)) if ed[i] in edits and halves[str(fn[i])] == "eval"]
        Xo, Xe = np.stack([orig[fn[i]] for i in rows]), X[rows]
        D = slog1p_(Xe.copy()) - slog1p_(Xo.copy())
        lo_s, hi_s, sup = E[f + "_lo"], E[f + "_hi"], E[f + "_support"]
        zo, ze = torch.as_tensor(pp.transform(Xo)), torch.as_tensor(pp.transform(Xe))
        y = net(zo).argmax(1)
        for t in SCALES:
            ins = (~(np.abs(D[:, ~sup]) > 1e-6).any(1)) & ((D[:, sup] >= t * lo_s[sup] - 1e-6) &
                                                          (D[:, sup] <= t * hi_s[sup] + 1e-6)).all(1)
            if not ins.any():
                continue
            m = torch.as_tensor(ins)
            lo, hi = family_box(zo[m], t, fams[f][0], fams[f][1], zlo, zhi)
            assert torch.all(ze[m] >= lo - 1e-3) and torch.all(ze[m] <= hi + 1e-3), (f, t)
            with torch.no_grad():
                lb_i, pre = ibp(net, lo, hi, y[m])
                c = torch.maximum(lb_i, crown(net, lo, hi, y[m], pre)) > 0
                assert torch.all(net(ze[m]).argmax(1)[c] == y[m][c]), (f, t)
            n_in += int(ins.sum()); n_cert += int(c.sum())
    assert n_in > 500, n_in
    assert n_cert > 0, "no certified case: the consistency check would be vacuous"
    print(f"     {n_in} (file, family, t) cases inside T_f(t), {n_cert} certified, 0 flipped")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("ok  ", t.__name__)
    print(f"all {len(tests)} family tests passed")
