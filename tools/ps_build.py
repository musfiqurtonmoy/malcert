"""Problem-space check, part 1 (REVISION_PLAN Stage 1b-1d): corpus, edits, feature extraction.

Runs in the `malcert-ps` environment (Python 3.7, lief 0.10.1, EMBER feature extractor):

    python tools/ps_build.py corpus     # copy 100 benign PE files from C:\\Windows\\System32
    python tools/ps_build.py edit       # apply edits E0-E9; every edit writes a NEW file
    python tools/ps_build.py extract    # EMBER v2 features -> ps_results/features.npz

Safety: files are only copied out of System32, never changed there. Edited files are written
under ps_corpus/edited/ and are NEVER executed; the only checks are static (re-parsing with LIEF).
Part 2 (tools/problem_space.py, in the `malcert` environment) analyses the features.
"""
import argparse, csv, hashlib, json, os, shutil, struct, subprocess, sys, zlib

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "ps_corpus")
ORIG = os.path.join(CORPUS, "orig")
EDITED = os.path.join(CORPUS, "edited")
RES = os.path.join(ROOT, "ps_results")
SYS32 = r"C:\Windows\System32"
UPX = os.path.join(ROOT, "ps_tools", "upx", "upx.exe")

# (edit code, variant) in the order they are applied. E0 is a control, not an attack: LIEF's builder
# rewrites the whole file, so E0 shows what E3/E4 change merely by rebuilding.
BYTE_EDITS = [("E1_overlay", v) for v in ("1k_random", "1k_benign", "64k_random", "64k_benign", "1m_random", "1m_benign")] + \
             [("E2_strings", "50"), ("E2_strings", "500"),
              ("E5_timestamp", "random"), ("E6_secnames", "random"),
              ("E7_header", "checksum"), ("E7_header", "dos_header"), ("E7_header", "dos_stub"),
              ("E8_strip", "signature"), ("E8_strip", "debug")]
LIEF_EDITS = [("E0_rebuild", "plain"), ("E0_rebuild", "imports"),
              ("E3_section", "4k_random"), ("E3_section", "4k_benign"),
              ("E3_section", "64k_random"), ("E3_section", "64k_benign"),
              ("E4_imports", "1"), ("E4_imports", "10")]
# "default" is the planned measurement. Most modern Microsoft binaries are built with Control Flow Guard,
# which UPX refuses to pack by default, so "force" (upx --force) is measured as well, labelled separately.
UPX_EDITS = [("E9_upx", "default"), ("E9_upx", "force")]
SIZES = {"1k": 1 << 10, "4k": 4 << 10, "64k": 64 << 10, "1m": 1 << 20}

KERNEL32 = ["GetTickCount", "Sleep", "GetCurrentProcessId", "GetCurrentThreadId", "GetSystemTime", "GetLocalTime",
            "GetVersion", "GetCommandLineA", "GetCommandLineW", "GetLastError", "SetLastError", "GetModuleHandleA",
            "GetModuleHandleW", "GetProcessHeap", "HeapAlloc", "HeapFree", "CloseHandle", "CreateFileA",
            "CreateFileW", "ReadFile", "WriteFile", "GetFileSize", "VirtualAlloc", "VirtualFree", "LoadLibraryA",
            "LoadLibraryW", "GetProcAddress", "FreeLibrary", "GetTempPathA", "GetTempPathW", "lstrlenA", "lstrlenW",
            "MultiByteToWideChar", "WideCharToMultiByte", "QueryPerformanceCounter", "GetSystemInfo", "GlobalAlloc",
            "GlobalFree", "LocalAlloc", "LocalFree", "GetComputerNameA", "GetComputerNameW", "GetSystemDirectoryA",
            "GetSystemDirectoryW", "GetWindowsDirectoryA", "GetWindowsDirectoryW", "GetEnvironmentVariableA",
            "GetEnvironmentVariableW", "GetFileAttributesA", "GetFileAttributesW"]
WORDS = ["update", "service", "config", "system", "windows", "microsoft", "driver", "network", "security",
         "manager", "client", "server", "report", "session", "content", "library", "profile", "storage"]


def seed_of(*parts):
    return zlib.crc32("|".join(parts).encode()) & 0x7FFFFFFF


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------- PE layout (byte level) -------------------------------
def pe_layout(d):
    """Offsets of the header fields the byte-level edits touch. d: bytes of a PE file."""
    if d[:2] != b"MZ":
        raise ValueError("not MZ")
    e = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e:e + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    opt_size = struct.unpack_from("<H", d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (96 if magic == 0x10B else 112)             # data directories: PE32 / PE32+
    ndd = struct.unpack_from("<I", d, dd - 4)[0]
    sect = opt + opt_size
    secs = []
    for i in range(nsec):
        o = sect + 40 * i
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", d, o + 8)
        secs.append(dict(off=o, vaddr=vaddr, vsize=vsize, roff=roff, rsize=rsize))
    return dict(e_lfanew=e, nsec=nsec, opt=opt, magic=magic, dd=dd, ndd=ndd, sect=sect, secs=secs)


def rva_to_off(L, rva):
    for s in L["secs"]:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["roff"] + (rva - s["vaddr"])
    return None


def cyc(b, n):
    return (b * (n // max(len(b), 1) + 1))[:n]


def strings_payload(n, rng):
    out = []
    for i in range(n):
        a, b, c = (WORDS[j] for j in rng.randint(0, len(WORDS), 3))
        kind = i % 3
        if kind == 0:
            s = "http://www.%s-%s.com/%s/%d" % (a, b, c, rng.randint(0, 10000))
        elif kind == 1:
            s = "C:\\Windows\\System32\\%s\\%s%d.dll" % (a, b, rng.randint(0, 100))
        else:
            s = "HKEY_LOCAL_MACHINE\\SOFTWARE\\%s\\%s\\%s" % (a.capitalize(), b.capitalize(), c.capitalize())
        out.append(s.encode("ascii") + b"\0")
    return b"".join(out)


def byte_edit(edit, variant, data, donor, name):
    """Return edited bytes, or None when the edit does not apply to this file."""
    rng = np.random.RandomState(seed_of(name, edit, variant))
    d = bytearray(data)
    L = pe_layout(data)
    if edit == "E1_overlay":
        size, kind = variant.split("_")
        n = SIZES[size]
        return bytes(d) + (rng.bytes(n) if kind == "random" else cyc(donor, n))
    if edit == "E2_strings":
        return bytes(d) + strings_payload(int(variant), rng)
    if edit == "E5_timestamp":                       # COFF TimeDateStamp: a date between 2000 and 2025
        struct.pack_into("<I", d, L["e_lfanew"] + 8, int(rng.randint(946684800, 1735689600)))
        return bytes(d)
    if edit == "E6_secnames":
        for s in L["secs"]:
            nm = b"." + bytes(rng.randint(97, 123, 7).astype(np.uint8))
            d[s["off"]:s["off"] + 8] = nm
        return bytes(d)
    if edit == "E7_header":
        if variant == "checksum":                    # optional-header CheckSum (ignored for user-mode images)
            struct.pack_into("<I", d, L["opt"] + 64, int(rng.randint(1, 0x7FFFFFFF)))
        elif variant == "dos_header":                # DOS header between e_magic and e_lfanew: unused by the loader
            d[2:0x3C] = rng.bytes(0x3C - 2)
        elif variant == "dos_stub":                  # DOS stub (and Rich header) between the DOS and PE headers
            if L["e_lfanew"] <= 0x40:
                return None
            d[0x40:L["e_lfanew"]] = rng.bytes(L["e_lfanew"] - 0x40)
        return bytes(d)
    if edit == "E8_strip":
        idx = 4 if variant == "signature" else 6     # data directory: Certificate Table / Debug
        if L["ndd"] <= idx:
            return None
        ent = L["dd"] + 8 * idx
        addr, size = struct.unpack_from("<II", d, ent)
        if size == 0 or addr == 0:
            return None                              # nothing to strip
        if variant == "signature":                   # addr is a FILE OFFSET for the certificate table
            struct.pack_into("<II", d, ent, 0, 0)
            if addr + size >= len(d) - 8:            # certificate at the end of the file: cut it off
                return bytes(d[:addr])
            d[addr:addr + size] = b"\0" * size
            return bytes(d)
        off = rva_to_off(L, addr)                    # debug: zero the raw debug data and the directory
        if off is None:
            return None
        for i in range(size // 28):
            o = off + 28 * i
            dsize, _, praw = struct.unpack_from("<III", d, o + 16)
            if 0 < praw and praw + dsize <= len(d):
                d[praw:praw + dsize] = b"\0" * dsize
        d[off:off + size] = b"\0" * size
        struct.pack_into("<II", d, ent, 0, 0)
        return bytes(d)
    raise ValueError(edit)


# ------------------------------------ LIEF edits ---------------------------------------
def lief_edit(edit, variant, src, dst, donor_path, name):
    import lief
    rng = np.random.RandomState(seed_of(name, edit, variant))
    b = lief.PE.parse(src)
    if b is None:
        return "failed:parse"
    builder_imports = False
    if edit == "E0_rebuild":
        builder_imports = variant == "imports"
    elif edit == "E3_section":
        size, kind = variant.split("_")
        n = SIZES[size]
        payload = rng.bytes(n) if kind == "random" else cyc(open(donor_path, "rb").read(), n)
        s = lief.PE.Section(".newsec")
        s.content = list(payload)
        b.add_section(s, lief.PE.SECTION_TYPES.DATA)
    elif edit == "E4_imports":
        have = set()
        k32 = None
        for lib in b.imports:
            if lib.name.lower() == "kernel32.dll":
                k32 = lib
            for e in lib.entries:
                if not e.is_ordinal:
                    have.add((lib.name.lower(), e.name))
        new = [f for f in KERNEL32 if ("kernel32.dll", f) not in have][:int(variant)]
        if len(new) < int(variant):
            return "skipped:not_enough_new_functions"
        if k32 is None:
            k32 = b.add_library("KERNEL32.dll")
        for f in new:
            k32.add_entry(f)
        builder_imports = True
    else:
        raise ValueError(edit)
    builder = lief.PE.Builder(b)
    if builder_imports:
        builder.build_imports(True)
        builder.patch_imports(True)
    builder.build()
    builder.write(dst)
    return "ok"


def lief_child(src, name, donor_path, skip):
    """Run all LIEF edits for one file, printing one JSON line per edit. LIEF can crash the
    interpreter on unusual files, so this runs in a child process that the parent restarts."""
    for edit, variant in LIEF_EDITS:
        key = edit + "/" + variant
        if key in skip:
            continue
        dst = os.path.join(EDITED, edit, variant, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        print(json.dumps({"start": key}), flush=True)
        try:
            status = lief_edit(edit, variant, src, dst, donor_path, name)
        except Exception as ex:                                  # noqa: BLE001 (record and continue)
            status = "failed:%s" % type(ex).__name__
        print(json.dumps({"done": key, "status": status}), flush=True)


def reparse(path):
    """Static check only: does LIEF still parse the edited file? Returns (ok, n_sections)."""
    import lief
    try:
        b = lief.PE.parse(path)
        return (b is not None and len(b.sections) > 0), (len(b.sections) if b is not None else 0)
    except Exception:                                            # noqa: BLE001
        return False, 0


# ------------------------------------- commands ----------------------------------------
def cmd_corpus(a):
    import lief
    os.makedirs(ORIG, exist_ok=True); os.makedirs(RES, exist_ok=True)
    if os.listdir(ORIG):
        raise SystemExit("%s is not empty; the corpus is built once (delete it yourself to rebuild)" % ORIG)
    cands = {"exe": [], "dll": []}
    for f in sorted(os.listdir(SYS32)):
        ext = f.lower().rsplit(".", 1)[-1]
        p = os.path.join(SYS32, f)
        if ext in cands and os.path.isfile(p):
            try:
                if a.min_size <= os.path.getsize(p) <= a.max_size:
                    cands[ext].append(f)
            except OSError:
                pass
    rng = np.random.RandomState(a.seed)
    rows, skipped = [], 0
    for ext in ("exe", "dll"):
        order = [cands[ext][i] for i in rng.permutation(len(cands[ext]))]
        got = 0
        for f in order:
            if got == a.n // 2:
                break
            src = os.path.join(SYS32, f)
            try:
                data = open(src, "rb").read()
                pe_layout(data)
                b = lief.PE.parse(src)
                if b is None or len(b.sections) == 0:
                    raise ValueError("lief returned nothing")
            except Exception:                                    # noqa: BLE001: unreadable or unparsable -> skip
                skipped += 1
                continue
            shutil.copyfile(src, os.path.join(ORIG, f))          # copy only; the system file is not touched
            rows.append(dict(file=f, kind=ext, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                             machine=str(b.header.machine).split(".")[-1], n_sections=len(b.sections),
                             n_import_funcs=len(b.imported_functions), n_export_funcs=len(b.exported_functions),
                             has_signature=int(b.has_signature), has_debug=int(b.has_debug),
                             overlay=len(b.overlay)))
            got += 1
    with open(os.path.join(RES, "corpus_manifest.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    sizes = [r["size"] for r in rows]
    print("corpus: %d files (%d exe, %d dll), %d candidates skipped as unparsable" % (
        len(rows), sum(r["kind"] == "exe" for r in rows), sum(r["kind"] == "dll" for r in rows), skipped))
    print("size: min %d, median %d, max %d bytes; total %.1f MB" % (
        min(sizes), int(np.median(sizes)), max(sizes), sum(sizes) / 1e6))
    print("with embedded signature: %d; with debug directory: %d; with overlay: %d; machines: %s" % (
        sum(r["has_signature"] for r in rows), sum(r["has_debug"] for r in rows),
        sum(r["overlay"] > 0 for r in rows), sorted(set(r["machine"] for r in rows))))


def cmd_edit(a):
    names = sorted(os.listdir(ORIG))
    only = set(a.only.split(",")) if a.only else None             # e.g. --only E9_upx: redo just these edits
    want = lambda edit: only is None or edit in only
    man_path = os.path.join(RES, "edits_manifest.csv")
    rows = []
    if only is not None and os.path.exists(man_path):             # keep the manifest rows of all other edits
        rows = [dict(r, size=int(r["size"]), n_sections=int(r["n_sections"]))
                for r in csv.DictReader(open(man_path)) if r["edit"] not in only]
    if any(want(e) for e, _ in UPX_EDITS) and not os.path.exists(UPX):
        raise SystemExit("UPX not found at %s" % UPX)
    for i, name in enumerate(names):
        src = os.path.join(ORIG, name)
        donor_path = os.path.join(ORIG, names[(i + 1) % len(names)])      # benign content comes from the next file
        data, donor = open(src, "rb").read(), open(donor_path, "rb").read()
        status = {}
        for edit, variant in [ev for ev in BYTE_EDITS if want(ev[0])]:
            dst = os.path.join(EDITED, edit, variant, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                out = byte_edit(edit, variant, data, donor, name)
                if out is None:
                    status[(edit, variant)] = "skipped:not_present"
                else:
                    open(dst, "wb").write(out)
                    status[(edit, variant)] = "ok"
            except Exception as ex:                              # noqa: BLE001
                status[(edit, variant)] = "failed:%s" % type(ex).__name__
        skip = set(e + "/" + v for e, v in LIEF_EDITS if not want(e))
        while len(skip) < len(LIEF_EDITS):                       # restart the child after a crash
            p = subprocess.run([sys.executable, os.path.abspath(__file__), "_lief", src, name, donor_path,
                                ",".join(sorted(skip))], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True)
            started = None
            for line in p.stdout.splitlines():
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if "start" in m:
                    started = m["start"]
                elif "done" in m:
                    status[tuple(m["done"].split("/"))] = m["status"]; skip.add(m["done"]); started = None
            if started is not None:                              # child died inside this edit
                status[tuple(started.split("/"))] = "failed:crash"; skip.add(started)
            elif p.returncode == 0:
                break
            else:
                break
        if os.path.exists(UPX):
            for edit, variant in [ev for ev in UPX_EDITS if want(ev[0])]:
                dst = os.path.join(EDITED, edit, variant, name)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.exists(dst):
                    os.remove(dst)                               # our own earlier output; upx will not overwrite
                # default settings; upx only reads src and writes dst. Nothing is executed except upx itself.
                cmd = [UPX, "-q"] + (["--force"] if variant == "force" else []) + ["-o", dst, src]
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                text = " ".join(p.stdout.split())                # upx wraps its messages over several lines
                why = ("GUARD_CF" if "GUARD_CF" in text else "integrity_check" if "integrity check" in text else
                       text.split("Exception:")[-1].strip()[:40].replace(",", ";") if "Exception:" in text else
                       "exit%d" % p.returncode)
                status[(edit, variant)] = "ok" if p.returncode == 0 and os.path.exists(dst) else (
                    "skipped:upx_refused:" + why)
        for (edit, variant), st in status.items():
            dst = os.path.join(EDITED, edit, variant, name)
            ok, nsec, size = False, 0, 0
            if st == "ok":
                if not os.path.exists(dst):
                    st = "failed:file_missing_after_write"       # e.g. removed by antivirus
                else:
                    size = os.path.getsize(dst)
                    ok, nsec = reparse(dst)
                    if not ok:
                        st = "failed:does_not_reparse"
            rows.append(dict(file=name, edit=edit, variant=variant, status=st, size=size, n_sections=nsec))
        if status:
            print("%3d/%d %-28s ok %2d / %2d" % (i + 1, len(names), name,
                                                 sum(r["status"] == "ok" for r in rows[-len(status):]), len(status)),
                  flush=True)
    os.makedirs(RES, exist_ok=True)
    order = {ev: j for j, ev in enumerate(BYTE_EDITS + LIEF_EDITS + UPX_EDITS)}
    rows.sort(key=lambda r: (r["file"], order[(r["edit"], r["variant"])]))
    with open(man_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "edit", "variant", "status", "size", "n_sections"])
        w.writeheader(); w.writerows(rows)
    print("\nedit / variant: ok, skipped, failed (of %d files)" % len(names))
    for edit, variant in BYTE_EDITS + LIEF_EDITS + UPX_EDITS:
        st = [r["status"] for r in rows if r["edit"] == edit and r["variant"] == variant]
        if st:
            fails = sorted(set(s for s in st if s.startswith("failed")))
            print("  %-12s %-12s %3d %3d %3d  %s" % (edit, variant, st.count("ok"), sum(s.startswith("skipped") for s in st),
                                                     sum(s.startswith("failed") for s in st), " ".join(fails)))


def _extract_one(path):
    import warnings
    warnings.filterwarnings("ignore")
    from ember.features import PEFeatureExtractor
    ex = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    return ex.feature_vector(open(path, "rb").read())


def cmd_extract(a):
    import multiprocessing as mp
    import lief
    man = list(csv.DictReader(open(os.path.join(RES, "edits_manifest.csv"))))
    names = sorted(os.listdir(ORIG))
    items = [(n, "orig", "orig", os.path.join(ORIG, n)) for n in names]
    items += [(r["file"], r["edit"], r["variant"], os.path.join(EDITED, r["edit"], r["variant"], r["file"]))
              for r in man if r["status"] == "ok"]
    with mp.Pool(a.workers) as pool:
        X = pool.map(_extract_one, [it[3] for it in items], chunksize=8)
        X2 = pool.map(_extract_one, [it[3] for it in items[:len(names)]], chunksize=8)   # determinism check
    X = np.stack(X).astype(np.float32)
    same = all(np.array_equal(x, y) for x, y in zip(X[:len(names)], X2))
    print("rows %d, dim %d; originals extracted twice give identical vectors: %s" % (X.shape[0], X.shape[1], same))
    bad = ~np.isfinite(X)
    if bad.any():                                                # say exactly where, then stop
        from collections import Counter
        rows = np.where(bad.any(1))[0]
        print("NON-FINITE values in %d rows, %d distinct features" % (len(rows), int(bad.any(0).sum())))
        print("  by edit/variant:", dict(Counter("%s/%s" % (items[i][1], items[i][2]) for i in rows)))
        print("  feature indices:", np.where(bad.any(0))[0].tolist()[:40])
        for i in rows[:5]:
            j = np.where(bad[i])[0]
            print("  e.g. %s %s/%s: features %s = %s" % (items[i][0], items[i][1], items[i][2], j.tolist()[:6],
                                                           X[i, j][:6].tolist()))
    if not same or X.shape[1] != 2381 or bad.any():
        raise SystemExit("feature extraction is not deterministic / not 2381-dimensional / not finite")
    np.savez_compressed(os.path.join(RES, "features.npz"), X=X,     # ("file" is savez's own argument name)
                        fname=np.array([it[0] for it in items]), edit=np.array([it[1] for it in items]),
                        variant=np.array([it[2] for it in items]),
                        lief_version=np.array(lief.__version__), numpy_version=np.array(np.__version__))
    print("saved", os.path.join(RES, "features.npz"))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_lief":
        _, _, src, name, donor_path, skip = sys.argv
        lief_child(src, name, donor_path, set(s for s in skip.split(",") if s))
        return
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("corpus")
    c.add_argument("--n", type=int, default=100)
    c.add_argument("--seed", type=int, default=0)
    c.add_argument("--min_size", type=int, default=16 << 10)
    c.add_argument("--max_size", type=int, default=4 << 20)
    ed = sub.add_parser("edit")
    ed.add_argument("--only", default="", help="comma-separated edit codes to (re)do, e.g. E9_upx; default: all")
    e = sub.add_parser("extract")
    e.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    {"corpus": cmd_corpus, "edit": cmd_edit, "extract": cmd_extract}[a.cmd](a)


if __name__ == "__main__":
    main()
