"""Memory dry run of data loading (REVISION_PLAN 1i.5). The PC has 7.9 GB of RAM.

    python tools/mem_dry_run.py

Each mode runs in a fresh process; its peak working set (RAM actually used) and peak commit are read
from Windows when it ends. No model is trained and the GPU is not used.
  subset     what run_all.py does today: 30K subset, fit, transform train/val/test
  full_lean  all 134,435 rows: load_full (once, float32), random split, standardise IN PLACE
The naive path on the full data (fit + transform with full-size temporaries) is NOT run: it needs several
copies of 1.28 GB and would push this PC into swap. Its size is estimated from the subset run instead.

Writes checks/memory_dry_run.json
"""
import argparse, ctypes, json, os, subprocess, sys, time
from ctypes import wintypes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class PMC(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def peaks():
    """(peak working set, peak commit) of this process in GB."""
    k32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    c = PMC(); c.cb = ctypes.sizeof(PMC)
    psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return c.PeakWorkingSetSize / 2 ** 30, c.PeakPagefileUsage / 2 ** 30


def child(mode):
    import numpy as np
    from malcert.config import get_config
    from malcert.data import Preprocessor, load_full, load_subset, split_indices
    os.chdir(ROOT)
    cfg = get_config("full")
    t0 = time.time()
    if mode == "subset":
        data = load_subset(cfg, seed=0)
        sp = split_indices(data, cfg, seed=0)
        pp = Preprocessor().fit(data["X"][sp["tr"]])
        Z = [pp.transform(data["X"][sp[k]]) for k in ("tr", "va", "te")]
        rows, held = len(data["y"]), sum(z.nbytes for z in Z) + data["X"].nbytes
    else:
        data = load_full(cfg)
        sp = split_indices(data, cfg, seed=0)
        Preprocessor().fit_transform_inplace(data["X"], sp["tr"])
        rows, held = len(data["y"]), data["X"].nbytes
        assert np.isfinite(data["X"][:1000]).all()
    ws, commit = peaks()
    print(json.dumps(dict(mode=mode, rows=rows, arrays_held_gb=round(held / 2 ** 30, 2), peak_working_set_gb=round(ws, 2),
                          peak_commit_gb=round(commit, 2), seconds=round(time.time() - t0, 1))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--child", default=None)
    a = ap.parse_args()
    if a.child:
        return child(a.child)
    out = []
    for mode in ("subset", "full_lean"):
        p = subprocess.run([sys.executable, os.path.abspath(__file__), "--child", mode], capture_output=True, text=True)
        if p.returncode != 0:
            raise SystemExit(f"{mode} failed:\n{p.stderr[-2000:]}")
        out.append(json.loads(p.stdout.strip().splitlines()[-1]))
        print(out[-1])
    sub, full = out
    one = 134435 * 2381 * 4 / 2 ** 30
    # the subset path peaks while the whole file is loaded and the subset copied; on the full data the naive
    # fit/transform would add about four more full-size float32 arrays (abs, log1p, sign, product) plus the output
    est = dict(one_full_copy_gb=round(one, 2), naive_full_estimate_gb=round(full["arrays_held_gb"] + 5 * one, 1))
    os.makedirs(os.path.join(ROOT, "checks"), exist_ok=True)
    json.dump(dict(runs=out, estimate=est, ram_total_gb=7.9), open(os.path.join(ROOT, "checks", "memory_dry_run.json"), "w"), indent=1)
    print(est)


if __name__ == "__main__":
    main()
