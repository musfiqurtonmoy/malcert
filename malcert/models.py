"""Networks and sound bound propagation (IBP and CROWN) for ReLU MLPs."""
import itertools
import torch
import torch.nn as nn
import torch.nn.functional as F


class MLP(nn.Module):
    """Plain Linear-ReLU stack (no BatchNorm/Dropout) so IBP/CROWN bounds are exact to implement."""

    def __init__(self, d_in, hidden=(512, 256), n_out=2):
        super().__init__()
        dims = [d_in, *hidden, n_out]
        self.linears = nn.ModuleList(nn.Linear(a, b) for a, b in zip(dims[:-1], dims[1:]))

    def forward(self, x):
        for i, lin in enumerate(self.linears):
            x = lin(x)
            if i < len(self.linears) - 1:
                x = F.relu(x)
        return x


class AblationNet(nn.Module):
    """Base classifier for group-ablation smoothing (C2a).
    Input: features of the kept groups (others set to 0 = training mean) + a 0/1 indicator
    per group, so the net knows which groups are missing rather than 'average'."""

    def __init__(self, d_in, n_groups, gid, hidden=(512, 256)):
        super().__init__()
        self.register_buffer("gid", torch.as_tensor(gid))
        self.net = MLP(d_in + n_groups, hidden)
        self.n_groups = n_groups

    def forward(self, x, gmask):                 # gmask: (B, G) float 0/1
        fmask = gmask[:, self.gid]
        return self.net(torch.cat([x * fmask, gmask], 1))

    def subsets(self, k):
        return list(itertools.combinations(range(self.n_groups), k))


class RandomAblationMLP(nn.Module):
    """Re-implementation of the base classifier of Giri et al. (2026): every forward pass removes each feature
    group independently with probability `drop` (set to 0 = training mean), then applies an MLP. It is a
    randomized classifier; with Gaussian noise added to the input, CERTIFY (Cohen et al.) gives an L2 radius,
    because the ablation randomness does not depend on the input."""

    def __init__(self, d_in, gid, drop, hidden=(512, 256)):
        super().__init__()
        self.register_buffer("gid", torch.as_tensor(gid))
        self.n_groups, self.drop = int(gid.max()) + 1, drop
        self.linears = MLP(d_in, hidden).linears          # same layers as MLP

    def forward(self, x):
        keep = (torch.rand(len(x), self.n_groups, device=x.device) >= self.drop).float()
        x = x * keep[:, self.gid]
        for i, lin in enumerate(self.linears):
            x = lin(x)
            if i < len(self.linears) - 1:
                x = F.relu(x)
        return x


# --------------------------------------------------------------------------------------
#  Bound propagation. Input region = box [xl, xu] (already contains mask / monotone /
#  domain constraints). Specification: margin  m(x) = logit_y - logit_{1-y}.
# --------------------------------------------------------------------------------------

def _spec(model, y):
    """Merged last layer: margin weights (B, h) and bias (B,)."""
    W, b = model.linears[-1].weight, model.linears[-1].bias
    sign = (2 * y - 1).float().unsqueeze(1)          # +1 for class 1, -1 for class 0
    return sign * (W[1] - W[0]).unsqueeze(0), sign.squeeze(1) * (b[1] - b[0])


def ibp(model, xl, xu, y):
    """Interval bound propagation. Returns margin lower bound and pre-activation boxes."""
    l, u = xl, xu
    pre = []
    for lin in model.linears[:-1]:
        c, r = (u + l) / 2, (u - l) / 2
        c = c @ lin.weight.t() + lin.bias
        r = r @ lin.weight.abs().t()
        pre.append((c - r, c + r))
        l, u = F.relu(c - r), F.relu(c + r)
    Wm, bm = _spec(model, y)
    c, r = (u + l) / 2, (u - l) / 2
    lb = (Wm * c).sum(1) - (Wm.abs() * r).sum(1) + bm
    return lb, pre


def crown(model, xl, xu, y, pre=None):
    """CROWN backward linear bound on the margin, using IBP boxes for intermediate layers
    (this is the 'CROWN-IBP' bound of Zhang et al., ICLR 2020)."""
    if pre is None:
        _, pre = ibp(model, xl, xu, y)
    Lam, const = _spec(model, y)
    for i in reversed(range(len(model.linears) - 1)):
        l, u = pre[i]
        act, unst = l >= 0, (l < 0) & (u > 0)
        denom = (u - l).clamp(min=1e-12)
        up_s = torch.where(act, torch.ones_like(l), torch.where(unst, u / denom, torch.zeros_like(l)))
        up_b = torch.where(unst, -u * l / denom, torch.zeros_like(l))
        lo_s = torch.where(act, torch.ones_like(l), torch.where(unst, (u > -l).float(), torch.zeros_like(l)))
        Lp, Ln = Lam.clamp(min=0), Lam.clamp(max=0)
        const = const + (Ln * up_b).sum(1)
        Lam = Lp * lo_s + Ln * up_s
        lin = model.linears[i]
        const = const + Lam @ lin.bias
        Lam = Lam @ lin.weight
    c, r = (xu + xl) / 2, (xu - xl) / 2
    return (Lam * c).sum(1) - (Lam.abs() * r).sum(1) + const


def family_box(x, t, lo_z, hi_z, zlo, zhi):
    """Edit-family threat set T_f(t) (REVISION_PLAN 2h): x + t * [lo_z, hi_z] per feature (lo_z = hi_z = 0 off the
    family's support), clipped to the natural bounds; x itself always stays inside.
    lo_z / hi_z are the family's measured change intervals divided by the run's standardisation sd."""
    lo = x + t * lo_z
    hi = x + t * hi_z
    lo = torch.maximum(lo, torch.minimum(zlo, x))
    hi = torch.minimum(hi, torch.maximum(zhi, x))
    return lo, hi


def load_families(sd, device, path=None):
    """Family intervals in standardised units for a run with standardisation sd: {family: (lo_z, hi_z)}."""
    import os
    import numpy as np
    from .data import FAMILIES
    path = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ps_results", "edit_families.npz")
    E = np.load(path)
    t = lambda a: torch.as_tensor(a / sd, dtype=torch.float32, device=device)
    return {f: (t(E[f + "_lo"]), t(E[f + "_hi"])) for f in FAMILIES}


def input_box(x, eps, mask, mono, zlo, zhi):
    """Constraint-aware L_inf box: immutable dims fixed, monotone dims only go up, and every dim
    stays inside its NATURAL bound [zlo, zhi] (data.natural_bounds: e.g. a histogram bin lies in
    [0, 1], a count is >= 0; +-inf where the feature has no such bound).

    Soundness: a natural bound holds for the feature vector of every PE file, so intersecting the
    box with it removes no point an attacker can reach. Draft v1 clipped to the training-set range
    instead, which is NOT sound: an edited file can exceed the largest value seen in training.
    The min/max with x keeps x itself inside the box in all cases."""
    lo = torch.where(mono, x, x - eps)
    hi = x + eps
    lo = torch.where(mask, lo, x)
    hi = torch.where(mask, hi, x)
    lo = torch.maximum(lo, torch.minimum(zlo, x))
    hi = torch.minimum(hi, torch.maximum(zhi, x))
    return lo, hi
