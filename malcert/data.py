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


# --------------------------------------------------------------------------------------
#  Feature units: the named pieces of the EMBER v2 vector, read from ember/features.py
#  (github.com/elastic/ember, commit d97a0b5). The threat-model annotation, the natural
#  bounds and the annotation table in the paper are all defined per unit.
#  kind:  hist   normalised histogram, every bin in [0, 1]
#         count  non-negative count or size
#         flag   0/1 indicator
#         value  other non-negative number (mean length, entropy, version field, timestamp, address)
#         hashed FeatureHasher output: signed and unbounded
# --------------------------------------------------------------------------------------
def _units():
    U = [("ByteHistogram", 0, 256, "hist"), ("ByteEntropyHistogram", 256, 512, "hist"),
         ("Strings.numstrings", 512, 513, "count"), ("Strings.avlength", 513, 514, "value"),
         ("Strings.printables", 514, 515, "count"), ("Strings.printabledist", 515, 611, "hist"),
         ("Strings.entropy", 611, 612, "value"), ("Strings.paths", 612, 613, "count"),
         ("Strings.urls", 613, 614, "count"), ("Strings.registry", 614, 615, "count"),
         ("Strings.MZ", 615, 616, "count")]
    for i, (n, k) in enumerate([("size", "count"), ("vsize", "count"), ("has_debug", "flag"), ("exports", "count"),
                                ("imports", "count"), ("has_relocations", "flag"), ("has_resources", "flag"),
                                ("has_signature", "flag"), ("has_tls", "flag"), ("symbols", "count")]):
        U.append(("General." + n, 616 + i, 617 + i, k))
    U.append(("Header.timestamp", 626, 627, "value"))
    for j, n in enumerate(["machine", "characteristics", "subsystem", "dll_characteristics", "magic"]):
        U.append(("Header." + n, 627 + 10 * j, 637 + 10 * j, "hashed"))
    for i, n in enumerate(["major_image_version", "minor_image_version", "major_linker_version",
                           "minor_linker_version", "major_os_version", "minor_os_version",
                           "major_subsystem_version", "minor_subsystem_version"]):
        U.append(("Header." + n, 677 + i, 678 + i, "value"))
    for i, n in enumerate(["sizeof_code", "sizeof_headers", "sizeof_heap_commit"]):
        U.append(("Header." + n, 685 + i, 686 + i, "count"))
    for i, n in enumerate(["n_sections", "n_zero_size", "n_empty_name", "n_rx", "n_w"]):
        U.append(("Section." + n, 688 + i, 689 + i, "count"))
    for j, n in enumerate(["sizes", "entropy", "vsizes", "entry_name", "entry_characteristics"]):
        U.append(("Section." + n, 693 + 50 * j, 743 + 50 * j, "hashed"))
    U += [("Imports.libraries", 943, 1199, "hashed"), ("Imports.functions", 1199, 2223, "hashed"),
          ("Exports.functions", 2223, 2351, "hashed")]
    for i, n in enumerate(["EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
                           "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE",
                           "LOAD_CONFIG_TABLE", "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR",
                           "CLR_RUNTIME_HEADER"]):
        U.append(("DataDir.%s.size" % n, 2351 + 2 * i, 2352 + 2 * i, "count"))
        U.append(("DataDir.%s.address" % n, 2352 + 2 * i, 2353 + 2 * i, "value"))
    assert [u[1] for u in U] == [0] + [u[2] for u in U[:-1]] and U[-1][2] == N_FEAT   # units tile the vector
    return U


FEATURE_UNITS = _units()


def natural_bounds():
    """Raw-space bounds that hold for EVERY PE file because of how the extractor computes the
    feature, not because of what the training set happens to contain:
        hist, flag            -> [0, 1]
        count, value          -> [0, +inf)
        hashed                -> (-inf, +inf)
    Verified on all 134,435 BODMAS rows and on the problem-space corpus (tests/test_threat_model.py)."""
    lo = np.full(N_FEAT, -np.inf, dtype=np.float64)
    hi = np.full(N_FEAT, np.inf, dtype=np.float64)
    for _, a, b, kind in FEATURE_UNITS:
        if kind != "hashed":
            lo[a:b] = 0.0
        if kind in ("hist", "flag"):
            hi[a:b] = 1.0
    return lo, hi


# --------------------------------------------------------------------------------------
#  Threat model (C1). Scope: the PE edits below, measured on benign files by the problem-space
#  check (tools/ps_build.py, tools/problem_space.py; results in ps_results/).
#    "in"      the threat model must contain every feature vector the edit produced
#    "out"     deliberately outside the threat model; measured to document why
#    "control" not an attack: LIEF rebuilding a file without changing it
# --------------------------------------------------------------------------------------
EDIT_SCOPE = {
    "E1_overlay": "in", "E2_strings": "in", "E3_section": "in", "E4_imports": "in", "E5_timestamp": "in",
    "E6_secnames": "in", "E7_header": "in",
    # E8 (strip the embedded signature / the debug directory) was "decide from evidence": every stripped
    # file still parses, and Anderson et al. (2018, Sec. 3.4) list "removing signer information" and
    # "manipulating debug info" among their functionality-preserving actions, so it is in scope.
    # It is the only edit that REMOVES content, which is what decides monotonicity.
    "E8_strip": "in",
    # E10 (plan 1i): header fields an attacker can set freely (linker / image versions; OS and subsystem
    # versions lowered; DYNAMIC_BASE and NX_COMPAT cleared). Plausibly functionality-preserving, not
    # verified by execution; taken as in scope so that the features they change count as mutable.
    "E10_hdrfields": "in",
    "E9_upx": "out", "E0_rebuild": "control",
}

DRAFT_V1_IMMUTABLE_GROUPS = {"Header(static)", "DataDir"}

# Edit families for edit-aware certified training (REVISION_PLAN 2h): threat sets T_f(t) built from the edit map.
FAMILIES = {"F_content": ["E1_overlay", "E2_strings", "E5_timestamp", "E7_header", "E10_hdrfields"],
            "F_section": ["E3_section", "E6_secnames"], "F_import": ["E4_imports"], "F_strip": ["E8_strip"]}


def threat_masks_draft_v1():
    """The annotation of draft v1, kept ONLY so the problem-space check can report how many real
    edits fall outside it. It was set by reasoning, not by measurement, and is not used by any
    experiment any more (see threat_masks)."""
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


def unit_index():
    """Unit name -> (start, end, kind, group name)."""
    gid = group_ids()
    return {n: (a, b, k, GROUP_NAMES[gid[a]]) for n, a, b, k in FEATURE_UNITS}


def masks_from_units(mutable_units, monotone_units):
    idx = unit_index()
    mutable = np.zeros(N_FEAT, bool)
    monotone = np.zeros(N_FEAT, bool)
    for n in mutable_units:
        mutable[idx[n][0]:idx[n][1]] = True
    for n in monotone_units:
        assert n in mutable_units and idx[n][2] == "count", n     # only mutable counts/sizes can be monotone
        monotone[idx[n][0]:idx[n][1]] = True
    return mutable, monotone


# Frozen annotation (REVISION_PLAN 1e). It is the output of the evidence rule in tools/problem_space.py,
# applied to ps_results/features.npz (150 benign files: 100 PE32+ from System32, 50 PE32 from SysWOW64;
# in-scope edits E1-E8 and E10; 4,169 edited files):
#   mutable   <=> changed by an in-scope edit in at least one file, or already mutable in draft v1
#   monotone  <=> mutable, a count or size, never decreased under any in-scope edit,
#                 and not listed in NOT_MONOTONE_BY_REASONING
# tools/problem_space.py and tests/test_threat_model.py fail if these lists and the evidence disagree.
MUTABLE_UNITS = [
    "ByteHistogram", "ByteEntropyHistogram",
    "Strings.numstrings", "Strings.avlength", "Strings.printables", "Strings.printabledist", "Strings.entropy",
    "Strings.paths", "Strings.urls", "Strings.registry", "Strings.MZ",
    "General.size", "General.vsize", "General.has_debug", "General.exports", "General.imports",
    "General.has_relocations", "General.has_signature",
    "Header.timestamp", "Header.sizeof_headers",
    # E10 only (1i): plausibly functionality-preserving, not verified by execution
    "Header.dll_characteristics", "Header.major_image_version", "Header.minor_image_version",
    "Header.major_linker_version", "Header.minor_linker_version", "Header.major_os_version",
    "Header.major_subsystem_version", "Header.minor_subsystem_version",
    "Header.minor_os_version",            # MUTABLE_BY_REASONING: conservative, not observed
    "Section.n_sections", "Section.n_zero_size", "Section.n_empty_name", "Section.n_rx", "Section.n_w",
    "Section.sizes", "Section.entropy", "Section.vsizes", "Section.entry_name", "Section.entry_characteristics",
    "Imports.libraries", "Imports.functions", "Exports.functions",
    "DataDir.IMPORT_TABLE.size", "DataDir.IMPORT_TABLE.address",
    "DataDir.CERTIFICATE_TABLE.size", "DataDir.CERTIFICATE_TABLE.address",
    "DataDir.DEBUG.size", "DataDir.DEBUG.address", "DataDir.IAT.size", "DataDir.IAT.address",
]
MONOTONE_UNITS = [
    "General.vsize", "General.exports", "General.imports", "Header.sizeof_headers",
    "Section.n_sections", "Section.n_zero_size", "Section.n_rx", "Section.n_w", "DataDir.IMPORT_TABLE.size",
]
# Counts that never decreased in the measurements but are NOT treated as increase-only, because an in-scope
# edit can lower them by construction. Dropping an increase-only constraint only enlarges the threat set,
# so these exceptions cannot make a certificate unsound.
# Units made mutable although no in-scope edit changed them (author decision 2026-11-13). Enlarging the
# mutable set only enlarges the threat set, so this cannot make a certificate unsound.
MUTABLE_BY_REASONING = {
    "Header.minor_os_version": "E10 lowers OS versions, but every corpus file has minor version 0, "
                               "so the edit never applied; a file with a non-zero minor version can lower it",
}
NOT_MONOTONE_BY_REASONING = {
    "Strings.registry": "E8 removes bytes, and every other string count decreased under it; "
                        "no stripped record in the corpus happened to contain a registry string",
    "Section.n_empty_name": "E6 renames sections, which removes an empty name; no corpus file has one",
}


def threat_masks():
    """Feature-level threat model (C1): (mutable, monotone) boolean masks over the 2,381 features.

    mutable[i]  : some in-scope edit (EDIT_SCOPE) changes feature i.
    monotone[i] : feature i is a count or size that the in-scope edits only increase.
    Scope of the claim: the threat set contains every feature vector that the in-scope edits produced
    on the measured files (checked by tests/test_threat_model.py), plus many vectors no edit produces.
    It is NOT a statement about edits outside EDIT_SCOPE (packing, repacking, obfuscation)."""
    return masks_from_units(MUTABLE_UNITS, MONOTONE_UNITS)


def attackable_groups():
    """Indices of the groups that contain at least one mutable feature. A group with no mutable
    feature cannot be changed by the attacker and does not count toward r."""
    mutable, _ = threat_masks()
    gid = group_ids()
    return [g for g in range(len(GROUP_NAMES)) if mutable[gid == g].any()]


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
    if cfg.split in ("temporal", "cutoff") and ts.isna().any():
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


SPLIT_SHARES = (0.7, 0.1, 0.2)          # train / val / test
# Random factor on family size when ordering families (assign_families). Chosen on split balance only (log 2-31):
# over 5 seeds, (0.8, 1.25) gave the smallest worst share error (2.7 points) while seeds still differ (test-family
# overlap 0.31); (1, 1) makes all seeds nearly identical (0.99), (0.5, 1.5) unbalances the parts (4.2 points).
FAMILY_ORDER_JITTER = (0.8, 1.25)


def assign_families(y, family, category, shares, rng):
    """Part index (0..len(shares)-1) for every sample, family-disjoint and category by category (log 2-29):
    each malware family takes the majority category of its samples; within each category, families are visited
    roughly largest first (size times a random factor, FAMILY_ORDER_JITTER) and each goes to the part with the largest
    absolute deficit against that category's target, so every part keeps its share and a category mix close to
    the whole. Benign files (no family) are split at random by the shares.
    Malware without a family is its own family."""
    y = np.asarray(y)
    shares = np.asarray(shares, dtype=float)
    part = np.empty(len(y), dtype=np.int64)
    mal = np.where(y == 1)[0]
    fam = np.array([f if isinstance(f, str) and f not in ("", "benign") else f"_single_{i}"
                    for i, f in zip(mal, np.asarray(family, dtype=object)[mal])])
    cat = np.asarray(category, dtype=object)[mal]
    names, inv = np.unique(fam, return_inverse=True)
    sizes = np.bincount(inv)
    fam_cat = np.array([pd.Series(cat[inv == j]).mode().iloc[0] for j in range(len(names))], dtype=object)
    part_of = np.empty(len(names), dtype=np.int64)
    for c in sorted(set(fam_cat)):
        js = np.where(fam_cat == c)[0]
        target = shares * sizes[js].sum()
        got = np.zeros(len(shares))
        # roughly largest first (random factor so seeds differ), each to the part with the largest absolute deficit:
        # large families fill the large part, small ones top up the small parts, so shares stay near target
        order = js[np.argsort(-(sizes[js] * rng.uniform(*FAMILY_ORDER_JITTER, len(js))))]
        for j in order:
            d = target - got
            p = int(rng.choice(np.flatnonzero(d == d.max())))     # ties at random, not always the first part
            part_of[j] = p
            got[p] += sizes[j]
    part[mal] = part_of[inv]
    ben = rng.permutation(np.where(y == 0)[0])
    cuts = np.round(np.cumsum(shares)[:-1] * len(ben)).astype(int)
    for p, idx in enumerate(np.split(ben, cuts)):
        part[idx] = p
    return part


def family_split(y, family, category, seed=0):
    """Family-disjoint split (REVISION_PLAN 3b): every malware family goes wholly to train, val or test,
    category by category (assign_families), 70/10/20."""
    rng = np.random.default_rng(seed)
    part = assign_families(y, family, category, SPLIT_SHARES, rng)
    return {k: rng.permutation(np.where(part == p)[0]) for p, k in enumerate(("tr", "va", "te"))}


def family_folds(y, family, category, pool, k=3, seed=0):
    """Grouped k-fold over the sample indices `pool` (2i: train + validation of the family split), category by
    category. Returns a list of k index arrays (positions in the full arrays)."""
    rng = np.random.default_rng(10_007 + seed)
    pool = np.asarray(pool)
    part = assign_families(np.asarray(y)[pool], np.asarray(family, dtype=object)[pool],
                           np.asarray(category, dtype=object)[pool], [1.0 / k] * k, rng)
    return [pool[part == f] for f in range(k)]


def split_indices(data, cfg, seed=0):
    n = len(data["y"])
    rng = np.random.default_rng(seed)
    if cfg.split == "family":
        return family_split(data["y"], data["family"], data["category"], seed)
    if cfg.split == "cutoff":
        # 3c: training period = up to the end of the cut-off month (random 90/10 train/val); test = every later file
        end = pd.Period(cfg.cutoff, freq="M").end_time.tz_localize("UTC")
        t = pd.DatetimeIndex(data["timestamp"])
        pre, post = np.where(t <= end)[0], np.where(t > end)[0]
        pre = rng.permutation(pre)
        a = int(0.9 * len(pre))
        return {"tr": pre[:a], "va": pre[a:], "te": rng.permutation(post)}
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


def slog1p_(X, chunk=4096):
    """Signed log1p in place on a float32 array, in row chunks (no full-size temporary)."""
    for a in range(0, len(X), chunk):
        v = X[a:a + chunk]
        np.multiply(np.sign(v), np.log1p(np.abs(v)), out=v)
    return X


def load_full(cfg):
    """All of BODMAS, loaded once: X stays float32 and is returned as the only full-size array
    (134,435 x 2,381 float32 = 1.28 GB). Same keys as load_subset; index = all rows."""
    d = np.load(cfg.data_npz, allow_pickle=False)
    X = d["X"]
    if X.dtype != np.float32:
        X = X.astype(np.float32)
    X = np.ascontiguousarray(X)
    y = d["y"].astype(np.int64)
    meta = pd.read_csv(cfg.meta_csv)
    cats = pd.read_csv(cfg.cat_csv).rename(columns={"sha256": "sha"})
    meta = meta.merge(cats, on="sha", how="left")
    meta["category"] = np.where(y == 1, meta["category"].fillna("unknown"), "benign")
    assert len(meta) == len(y) == len(X)
    ts = pd.to_datetime(meta["timestamp"].values, format="mixed", errors="coerce", utc=True)
    return dict(X=X, y=y, category=meta["category"].values, family=meta["family"].fillna("benign").values,
                timestamp=ts, index=np.arange(len(y)))


class Preprocessor:
    """Signed log1p then z-score. Both steps are monotone increasing per feature, so
    'feature can only increase' in raw space is still 'can only increase' in z-space."""

    def fit(self, X):
        Z = np.sign(X) * np.log1p(np.abs(X))
        self.mu = Z.mean(0)
        self.sd = Z.std(0)
        self.sd[self.sd < 1e-6] = 1.0
        return self

    def transform(self, X):
        Z = np.sign(X) * np.log1p(np.abs(X))
        return ((Z - self.mu) / self.sd).astype(np.float32)

    def inverse(self, Z):
        """Raw feature values from standardised ones (exact inverse of transform, up to float rounding).
        Used to score attacked vectors with models trained on raw features (LightGBM)."""
        S = np.asarray(Z, dtype=np.float64) * self.sd + self.mu
        return (np.sign(S) * np.expm1(np.abs(S))).astype(np.float32)

    def fit_rows(self, X, train_idx, chunk=4096):
        """fit(X[train_idx]) without a full-size copy: statistics accumulated in float64 over row chunks
        (used by the full-data check; X itself is left unchanged)."""
        train_idx = np.sort(np.asarray(train_idx))
        s = np.zeros(X.shape[1]); ss = np.zeros(X.shape[1])
        for a in range(0, len(train_idx), chunk):
            v = X[train_idx[a:a + chunk]].astype(np.float64)
            v = np.sign(v) * np.log1p(np.abs(v))
            s += v.sum(0); ss += (v * v).sum(0)
        mu = s / len(train_idx)
        sd = np.sqrt(np.maximum(ss / len(train_idx) - mu * mu, 0.0))
        sd[sd < 1e-6] = 1.0
        self.mu, self.sd = mu.astype(np.float32), sd.astype(np.float32)
        return self

    def fit_transform_inplace(self, X, train_idx, chunk=4096):
        """Memory-lean equivalent of fit(X[train_idx]) followed by transform(X), for the full dataset.
        X (float32, C-contiguous) is OVERWRITTEN with its standardised values; nothing of X's size is
        allocated: the work is done in row chunks, and the statistics are accumulated in float64.
        Use it only where the raw values are no longer needed (LightGBM, which takes raw features, first).
        Agrees with fit/transform to float32 rounding (tests/test_threat_model.py)."""
        assert X.dtype == np.float32 and X.flags.c_contiguous and X.flags.writeable
        slog1p_(X, chunk)
        train_idx = np.sort(np.asarray(train_idx))
        s = np.zeros(X.shape[1]); ss = np.zeros(X.shape[1])
        for a in range(0, len(train_idx), chunk):
            v = X[train_idx[a:a + chunk]].astype(np.float64)
            s += v.sum(0); ss += (v * v).sum(0)
        mu = s / len(train_idx)
        sd = np.sqrt(np.maximum(ss / len(train_idx) - mu * mu, 0.0))
        sd[sd < 1e-6] = 1.0
        self.mu, self.sd = mu.astype(np.float32), sd.astype(np.float32)
        for a in range(0, len(X), chunk):
            v = X[a:a + chunk]
            v -= self.mu
            v /= self.sd
        return X

    def bounds(self):
        """natural_bounds() mapped to standardised space (+-inf where a feature has no bound).
        The transform is increasing per feature, so a raw bound maps to a bound.
        These replace the training-set range used in draft v1, which was not a sound limit:
        an attacker can exceed any value that happens to be the largest in the training set."""
        lo, hi = natural_bounds()
        with np.errstate(invalid="ignore"):
            zlo = (np.sign(lo) * np.log1p(np.abs(lo)) - self.mu) / self.sd
            zhi = (np.sign(hi) * np.log1p(np.abs(hi)) - self.mu) / self.sd
        return zlo.astype(np.float32), zhi.astype(np.float32)
