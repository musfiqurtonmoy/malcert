"""C2: certificates.
  (a) feature-group ablation smoothing  -> deterministic certificate against changing
      ANY values in up to r mutable feature groups (an L0-over-groups threat model)
  (b) Gaussian randomized smoothing (Cohen et al. 2019) with noise on all features
      ('isotropic') or only on the attacker-mutable subspace ('subspace')."""
from math import comb
import numpy as np
import torch
from scipy.stats import beta, norm


# ------------------------------- (a) group ablation ----------------------------------
@torch.no_grad()
def ablation_votes(net, X, k, batch=2048):
    """Vote counts (N, 2) over all C(G, k) kept-group subsets."""
    subs = net.subsets(k)
    G = net.n_groups
    masks = torch.zeros(len(subs), G, device=X.device)
    for i, s in enumerate(subs):
        masks[i, list(s)] = 1
    votes = torch.zeros(len(X), 2, device=X.device)
    per = max(1, batch // len(subs))
    for a in range(0, len(X), per):
        xb = X[a:a + per]
        xr = xb.repeat_interleave(len(subs), 0)
        mr = masks.repeat(len(xb), 1)
        pred = net(xr, mr).argmax(1).view(len(xb), len(subs))
        votes[a:a + per, 1] = pred.sum(1).float()
        votes[a:a + per, 0] = len(subs) - votes[a:a + per, 1]
    return votes


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
