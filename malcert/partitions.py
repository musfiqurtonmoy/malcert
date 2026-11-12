"""Feature partitions (groups) for the group-ablation certificate (REVISION_PLAN 2b).

"ember": the 9 feature blocks of the EMBER extractor (timestamp moved to General), as in draft v1.
"aligned*": edit-aligned candidates built ONLY from the co-change data of the problem-space check
(ps_results/unit_evidence.csv): features that the same in-scope edits change share a group, so a real edit
touches as few groups as possible. Groups whose features no in-scope edit changes and that hold no mutable
feature are not attackable; their views are permanent votes.

Building blocks (feature units, see data.FEATURE_UNITS):
  CONTENT  byte and byte-entropy histograms, all string features, file size, has_relocations, COFF timestamp
           (changed by every in-scope edit: any edit changes bytes)
  HDRMUT   DllCharacteristics and the 8 version fields (E10; minor OS version conservative)
  SIGDBG   has_debug, has_signature, certificate and debug data-directory entries (E8)
  SECTION  sizeof_headers, virtual size, all section features (E3, E6; E4 and E8 through the rebuild/entropy)
  IMPORTS  import and export counts and hashes, import-table and IAT entries (E4; exports conservative)
  IMMHDR   immutable header and general fields (machine, characteristics, subsystem, magic, sizeof_code,
           sizeof_heap_commit, has_resources, has_tls, symbols)
  IMMDD    the 11 data-directory entries no in-scope edit changes
"""
import numpy as np

from .data import FEATURE_UNITS, N_FEAT, group_ids, threat_masks, GROUP_NAMES

_VERSIONS = ["major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
             "major_os_version", "minor_os_version", "major_subsystem_version", "minor_subsystem_version"]
_IMM_DD = ["EXPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "BASE_RELOCATION_TABLE", "ARCHITECTURE",
           "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT", "DELAY_IMPORT_DESCRIPTOR",
           "CLR_RUNTIME_HEADER"]
BLOCKS = {
    "CONTENT": ["ByteHistogram", "ByteEntropyHistogram", "Strings.*", "General.size", "General.has_relocations",
                "Header.timestamp"],
    "HDRMUT": ["Header.dll_characteristics"] + ["Header." + v for v in _VERSIONS],
    "SIGDBG": ["General.has_debug", "General.has_signature", "DataDir.CERTIFICATE_TABLE.*", "DataDir.DEBUG.*"],
    "SECTION": ["Header.sizeof_headers", "General.vsize", "Section.*"],
    "IMPORTS": ["General.imports", "General.exports", "Imports.*", "Exports.functions",
                "DataDir.IMPORT_TABLE.*", "DataDir.IAT.*"],
    "IMMHDR": ["General.has_resources", "General.has_tls", "General.symbols", "Header.machine",
               "Header.characteristics", "Header.subsystem", "Header.magic", "Header.sizeof_code",
               "Header.sizeof_heap_commit"],
    "IMMDD": ["DataDir.%s.*" % n for n in _IMM_DD],
}
# candidate -> list of groups, each group a list of blocks
CANDIDATES = {
    "aligned4": [["CONTENT", "HDRMUT", "SIGDBG"], ["SECTION"], ["IMPORTS"], ["IMMHDR", "IMMDD"]],
    "aligned5": [["CONTENT", "HDRMUT", "SIGDBG"], ["SECTION"], ["IMPORTS"], ["IMMHDR"], ["IMMDD"]],
    "aligned7": [["CONTENT"], ["HDRMUT"], ["SIGDBG"], ["SECTION"], ["IMPORTS"], ["IMMHDR"], ["IMMDD"]],
}
PARTITIONS = ["ember"] + list(CANDIDATES)


def _match(pattern, unit):
    return unit == pattern or (pattern.endswith(".*") and unit.startswith(pattern[:-1]))


def block_of_unit():
    out = {}
    for n, _, _, _ in FEATURE_UNITS:
        hits = [b for b, pats in BLOCKS.items() if any(_match(p, n) for p in pats)]
        assert len(hits) == 1, (n, hits)
        out[n] = hits[0]
    return out


def partition(name):
    """(gid, group names) for a partition: gid[i] = group of feature i."""
    if name == "ember":
        return group_ids(), list(GROUP_NAMES)
    groups = CANDIDATES[name]
    b2g = {b: g for g, bl in enumerate(groups) for b in bl}
    bou = block_of_unit()
    gid = np.empty(N_FEAT, dtype=np.int64)
    for n, a, b, _ in FEATURE_UNITS:
        gid[a:b] = b2g[bou[n]]
    return gid, ["+".join(bl) for bl in groups]


def attackable(gid):
    """Groups containing at least one mutable feature."""
    mutable, _ = threat_masks()
    return [g for g in range(int(gid.max()) + 1) if mutable[gid == g].any()]
