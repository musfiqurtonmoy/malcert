"""Soundness tests for the certificates. Run:  python -m pytest -q tests   (or python tests/test_soundness.py)"""
import itertools, os, sys
from math import comb
import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from malcert.models import MLP, ibp, crown, input_box


def test_bounds_are_sound():
    """IBP and CROWN lower bounds must never exceed the true margin anywhere in the box."""
    torch.manual_seed(0)
    d = 40
    net = MLP(d, (32, 16)).eval()
    x = torch.randn(8, d)
    y = torch.randint(0, 2, (8,))
    mask = torch.rand(d) > 0.2
    mono = mask & (torch.rand(d) > 0.7)
    zmin, zmax = torch.full((d,), -3.0), torch.full((d,), 3.0)
    lo, hi = input_box(x, 0.3, mask, mono, zmin, zmax)
    lb_i, pre = ibp(net, lo, hi, y)
    lb_c = crown(net, lo, hi, y, pre)
    with torch.no_grad():
        for _ in range(2000):
            xs = lo + (hi - lo) * torch.rand_like(lo)
            z = net(xs)
            m = (z.gather(1, y[:, None]) - z.gather(1, (1 - y)[:, None])).squeeze(1)
            assert torch.all(m >= lb_i - 1e-5) and torch.all(m >= lb_c - 1e-5)
    assert torch.all(lo[:, ~mask] == x[:, ~mask]) and torch.all(hi[:, ~mask] == x[:, ~mask])
    assert torch.all(lo[:, mono] >= x[:, mono] - 1e-7)


def test_ablation_count_is_exact():
    """Delta_r = C(G,k) - C(G-r,k) is the max number of k-subsets touching any r groups."""
    G = 9
    for k in (1, 2, 3):
        subs = list(itertools.combinations(range(G), k))
        for r in range(0, 5):
            worst = max(sum(1 for s in subs if set(s) & set(A)) for A in itertools.combinations(range(G), r))
            assert worst == comb(G, k) - comb(G - r, k)


if __name__ == "__main__":
    test_bounds_are_sound(); test_ablation_count_is_exact(); print("all soundness tests passed")
