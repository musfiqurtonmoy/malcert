"""BODMAS loading, 30K stratified subset, EMBER v2 feature groups and the threat-model masks.

EMBER v2 layout (2,381 features) used by BODMAS:
    ByteHistogram 256 | ByteEntropyHistogram 256 | Strings 104 | General 10 | Header 62 |
    Section 255 | Imports 1280 | Exports 128 | DataDirectories 30
"""
import numpy as np
import pandas as pd

EMBER_BLOCKS = [
    ("ByteHistogram", 0, 256), ("ByteEntropyHistogram", 256, 512), ("Strings", 512, 616),
    ("General", 616, 626), ("Header", 626, 688), ("Section", 688, 943),
    ("Imports", 943, 2223), ("Exports", 2223, 2351), ("DataDirectories", 2351, 2381),
]
N_FEAT = 2381
TIMESTAMP_IDX = 626            # first Header feature = COFF timestamp (freely editable)

# Groups used for ablation certificates. The timestamp is moved from Header to General so
# that "Header (static)" contains only fields an attacker cannot change without breaking
# the binary, which makes it an immutable group.
GROUP_NAMES = ["ByteHist", "ByteEntropy", "Strings", "General+TS", "Header(static)",
               "Section", "Imports", "Exports", "DataDir"]
IMMUTABLE_GROUPS = {"Header(static)", "DataDir"}


def group_ids() -> np.ndarray:
    gid = np.empty(N_FEAT, dtype=np.int64)
    for g, (_, a, b) in enumerate(EMBER_BLOCKS):
        gid[a:b] = g
    gid[TIMESTAMP_IDX] = 3     # General+TS
    return gid


def threat_masks():
    """Feature-level threat model (C1).

    mutable[i]  : attacker may change feature i with functionality-preserving edits
                  (append bytes/overlay, add strings, add a section, add imports/exports,
                  edit the timestamp).
    monotone[i] : feature i can only increase under append-only edits (counts and sizes).
    The model is an over-approximation of real problem-space edits, so certificates
    proved against it are sound for the real attacker too.
    """
    mutable = np.zeros(N_FEAT, bool)
    monotone = np.zeros(N_FEAT, bool)
    for name, a, b in EMBER_BLOCKS:
        if name in ("ByteHistogram", "ByteEntropyHistogram", "Strings", "Section", "Imports", "Exports"):
            mutable[a:b] = True
    # General: size, vsize, exports, imports  (has_debug, relocations, signature... fixed)
    for off in (0, 1, 3, 4):
        mutable[616 + off] = monotone[616 + off] = True
    mutable[TIMESTAMP_IDX] = True
    # Strings: numstrings, printables, paths, urls, registry, MZ are counts
    for idx in (512, 514, 612, 613, 614, 615):
        monotone[idx] = True
    # Section summary counts: #sections, #zero-size, #empty-name, #RX, #W
    monotone[688:693] = True
    return mutable, monotone


def load_subset(cfg, seed=0):
    """Return X (raw float32), y, category (str, 'benign' for benign), family, timestamp."""
    d = np.load(cfg.data_npz, allow_pickle=False)
    X = d["X"]
    sel, y, meta = select_subset(cfg, seed)
    # BODMAS mixes "YYYY-mm-dd HH:MM:SS+00:00" with 3,712 rows lacking the "+00:00" suffix. pandas >= 2
    # infers one format from the first row and would turn the others into NaT, which the temporal split
    # then sorts last, i.e. into the "future" test set. format="mixed" parses each row on its own;
    # suffix-less rows are read as UTC, the zone of every other BODMAS timestamp.
    ts = pd.to_datetime(meta["timestamp"].values[sel], format="mixed", errors="coerce", utc=True)
    if cfg.split == "temporal" and ts.isna().any():
        raise ValueError(f"{int(ts.isna().sum())} unparseable timestamps would leak into the temporal test set")
    return dict(X=X[sel].astype(np.float32), y=y[sel], category=meta["category"].values[sel],
                family=meta["family"].fillna("benign").values[sel], timestamp=ts, index=sel)


def select_subset(cfg, seed=0):
    """Choose the stratified subset without loading the feature matrix.
    Returns (sel, y, meta): sorted row indices into the full BODMAS arrays, all labels, merged metadata."""
    d = np.load(cfg.data_npz, allow_pickle=False)
    y = d["y"].astype(np.int64)
    meta = pd.read_csv(cfg.meta_csv)
    cats = pd.read_csv(cfg.cat_csv).rename(columns={"sha256": "sha"})
    meta = meta.merge(cats, on="sha", how="left")
    meta["category"] = np.where(y == 1, meta["category"].fillna("unknown"), "benign")
    assert len(meta) == len(y)

    rng = np.random.default_rng(seed)
    mal_idx = np.where(y == 1)[0]
    ben_idx = np.where(y == 0)[0]
    # malware: stratified by category, keeping at least min(n, 5) of every category
    mcat = meta["category"].values[mal_idx]
    frac = cfg.n_malware / len(mal_idx)
    take = {}
    for c in np.unique(mcat):
        n_c = int((mcat == c).sum())
        take[c] = min(n_c, max(int(round(frac * n_c)), min(n_c, 5)))
    largest = max(take, key=take.get)
    take[largest] += cfg.n_malware - sum(take.values())
    sel_m = np.concatenate([rng.choice(mal_idx[mcat == c], take[c], replace=False) for c in take])
    sel_b = rng.choice(ben_idx, cfg.n_benign, replace=False)
    sel = np.sort(np.concatenate([sel_m, sel_b]))
    return sel, y, meta


def split_indices(data, cfg, seed=0):
    n = len(data["y"])
    rng = np.random.default_rng(seed)
    if cfg.split == "temporal":
        order = np.argsort(data["timestamp"].values.astype("datetime64[ns]"))
    else:   # stratified on category (which also stratifies the label)
        order = np.empty(0, dtype=np.int64)
        parts = {"tr": [], "va": [], "te": []}
        for c in np.unique(data["category"]):
            idx = rng.permutation(np.where(data["category"] == c)[0])
            a, b = int(0.7 * len(idx)), int(0.8 * len(idx))
            parts["tr"].append(idx[:a]); parts["va"].append(idx[a:b]); parts["te"].append(idx[b:])
        return {k: rng.permutation(np.concatenate(v)) for k, v in parts.items()}
    a, b = int(0.7 * n), int(0.8 * n)
    return {"tr": order[:a], "va": order[a:b], "te": order[b:]}


class Preprocessor:
    """Signed log1p then z-score. Both steps are monotone increasing per feature, so
    'feature can only increase' in raw space is still 'can only increase' in z-space."""

    def fit(self, X):
        Z = np.sign(X) * np.log1p(np.abs(X))
        self.mu = Z.mean(0)
        self.sd = Z.std(0)
        self.sd[self.sd < 1e-6] = 1.0
        Zs = (Z - self.mu) / self.sd
        self.zmin, self.zmax = Zs.min(0), Zs.max(0)
        return self

    def transform(self, X):
        Z = np.sign(X) * np.log1p(np.abs(X))
        return ((Z - self.mu) / self.sd).astype(np.float32)
