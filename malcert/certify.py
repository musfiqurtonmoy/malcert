"""C2: certificates.
  (a) feature-group ablation smoothing  -> deterministic certificate against changing
      ANY values in up to r mutable feature groups (an L0-over-groups threat model)
  (b) Gaussian randomized smoothing (Cohen et al. 2019) with noise on all features
      ('isotropic') or only on the attacker-mutable subspace ('subspace')."""
import itertools
from math import comb
import numpy as np
import torch
from scipy.stats import beta, norm


# ------------------------------- (a) group ablation ----------------------------------
@torch.no_grad()
def ablation_view_votes(net, X, k, batch=2048):
    """Per-view malware votes (N, V) bool, views in the order of net.subsets(k)."""
    subs = net.subsets(k)
    G = net.n_groups
    masks = torch.zeros(len(subs), G, device=X.device)
    for i, s in enumerate(subs):
        masks[i, list(s)] = 1
    out = torch.zeros(len(X), len(subs), dtype=torch.bool, device=X.device)
    per = max(1, batch // len(subs))
    for a in range(0, len(X), per):
        xb = X[a:a + per]
        xr = xb.repeat_interleave(len(subs), 0)
        mr = masks.repeat(len(xb), 1)
        out[a:a + per] = net(xr, mr).argmax(1).view(len(xb), len(subs)).bool()
    return out


def votes_from_views(view_mal):
    """(N, V) bool malware votes -> vote counts (N, 2) as float tensor [benign, malware]."""
    m = view_mal.sum(1).float()
    return torch.stack([view_mal.shape[1] - m, m], 1)


@torch.no_grad()
def ablation_votes(net, X, k, batch=2048):
    """Vote counts (N, 2) over all C(G, k) kept-group subsets."""
    return votes_from_views(ablation_view_votes(net, X, k, batch))


def ceiling_r(G, k):
    """Largest r for which ANY vote-counting certificate over the C(G, k) views can certify a sample:
    the C(G-r, k) views an attack on r groups cannot touch must outnumber the C(G, k) - C(G-r, k) it can.
    (With all untouched views correct and all touched views wrong, n_y - n_other = 2 C(G-r,k) - C(G,k).)"""
    r = 0                                      # r = 0 is always certifiable in principle
    while r + 1 <= G and 2 * comb(G - r - 1, k) > comb(G, k):
        r += 1
    return r


def ablation_certify_exact(view_mal, y, subsets, attackable, max_r):
    """Exact worst case (REVISION_PLAN 2a). For every set A of r ATTACKABLE groups, every view that keeps a
    group in A is assumed to vote for the wrong class. Certified at r iff for all such A:
        correct votes among untouched views > wrong votes among untouched views + number of touched views.
    Strict inequality: a tie is not certified (conservative). Returns (N, max_r + 1) bool.
    Views keeping only non-attackable groups are never touched: they are permanent votes."""
    correct = (view_mal.long() == y[:, None].long()).float()            # (N, V)
    keep = np.zeros((len(subsets), max(max(s) for s in subsets) + 1), bool)
    for i, s in enumerate(subsets):
        keep[i, list(s)] = True
    out = np.zeros((len(y), max_r + 1), bool)
    dev = correct.device
    for r in range(max_r + 1):
        As = list(itertools.combinations(attackable, r))
        if not As:
            break
        touched = np.stack([keep[:, list(A)].any(1) if A else np.zeros(len(subsets), bool) for A in As])   # (nA, V)
        u = torch.as_tensor(~touched, dtype=torch.float32, device=dev)
        cu = correct @ u.T                                                # correct among untouched  (N, nA)
        wu = (1 - correct) @ u.T                                          # wrong among untouched
        t = torch.as_tensor(touched.sum(1), dtype=torch.float32, device=dev)
        out[:, r] = ((cu - wu - t) > 0).all(1).cpu().numpy()
    return out


def ablation_certify(votes, y, G, k, max_r):
    """Certified correct at r  <=>  n_y - n_other > 2 * (#subsets touching any r groups).
    A subset is affected only if it keeps at least one modified group; the worst case
    over r groups is C(G,k) - C(G-r,k). Returns (N, max_r+1) boolean matrix."""
    vy = votes.gather(1, y[:, None]).squeeze(1)
    vo = votes.sum(1) - vy
    gap = (vy - vo).cpu().numpy()
    out = np.zeros((len(gap), max_r + 1), bool)
    for r in range(max_r + 1):
        affected = comb(G, k) - comb(G - r, k)
        out[:, r] = gap > 2 * affected
    return out


# ------------------------------ (b) Gaussian smoothing --------------------------------
@torch.no_grad()
def _sample_counts(model, x, sigma, noise_mask, n, batch):
    counts = torch.zeros(2, device=x.device)
    rem = n
    while rem > 0:
        b = min(batch, rem)
        noise = torch.randn(b, x.numel(), device=x.device) * sigma * noise_mask
        pred = model(x[None] + noise).argmax(1)
        counts += torch.bincount(pred, minlength=2).float()
        rem -= b
    return counts


def smooth_certify(model, X, y, sigma, noise_mask, n0, n, alpha, batch=4096):
    """CERTIFY from Cohen et al. Returns predictions (-1 = abstain) and L2 radii
    (radius is measured in the subspace where noise is applied)."""
    model.eval()
    preds, radii = [], []
    for x in X:
        c0 = _sample_counts(model, x, sigma, noise_mask, n0, batch)
        cA = int(c0.argmax())
        nA = int(_sample_counts(model, x, sigma, noise_mask, n, batch)[cA])
        pA = beta.ppf(alpha, nA, n - nA + 1) if nA > 0 else 0.0
        if pA < 0.5:
            preds.append(-1); radii.append(0.0)
        else:
            preds.append(cA); radii.append(sigma * norm.ppf(pA))
    return np.array(preds), np.array(radii)
