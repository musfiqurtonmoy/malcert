"""Groups touched by each in-scope edit under each partition, and the certifiability ceiling (REVISION_PLAN 2a, 2b).
Uses only ps_results/features.npz (the problem-space measurements); no model, no test data.

    python tools/grouping_footprint.py

Writes ps_results/grouping_footprint.csv: partition, edit, files, r_needed (max groups touched over files),
median groups, share of files touching <= 1/2/3 groups; and ps_results/ceiling.csv.
"""
import os, sys
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.certify import ceiling_r                                 # noqa: E402
from malcert.data import EDIT_SCOPE                                    # noqa: E402
from malcert.partitions import PARTITIONS, attackable, partition       # noqa: E402

RES = os.path.join(ROOT, "ps_results")
EDITS = [e for e, s in EDIT_SCOPE.items() if s == "in"]


def footprints(gid):
    """{edit: array of #groups touched per edited file}, plus a check that only attackable groups change."""
    F = np.load(os.path.join(RES, "features.npz"))
    X, fn, ed = F["X"], F["fname"], F["edit"]
    orig = {f: X[i] for i, f in enumerate(fn) if ed[i] == "orig"}
    att = set(attackable(gid))
    G = int(gid.max()) + 1
    out = {e: [] for e in EDITS}
    for i in range(len(X)):
        if ed[i] in out:
            g = set(gid[X[i] != orig[fn[i]]])
            assert g <= att, (fn[i], ed[i], g - att)
            out[ed[i]].append(len(g))
    return {e: np.array(v) for e, v in out.items()}, G, att


def main():
    rows, ceil = [], []
    for p in PARTITIONS:
        gid, names = partition(p)
        fp, G, att = footprints(gid)
        for k in (1, 2, 3, 4, 5):
            ceil.append(dict(partition=p, G=G, attackable=len(att), k=k, views=int(np.math.comb(G, k)) if hasattr(np, "math") else None,
                             max_r=ceiling_r(G, k)))
        for e, n in fp.items():
            rows.append(dict(partition=p, G=G, n_attackable=len(att), edit=e, files=len(n), r_needed=int(n.max()),
                             groups_median=float(np.median(n)), le1=float((n <= 1).mean()), le2=float((n <= 2).mean()),
                             le3=float((n <= 3).mean())))
    R, C = pd.DataFrame(rows), pd.DataFrame(ceil)
    R.to_csv(os.path.join(RES, "grouping_footprint.csv"), index=False)
    C.to_csv(os.path.join(RES, "ceiling.csv"), index=False)
    print(R.pivot(index="edit", columns="partition", values="r_needed").reindex(EDITS).to_string())
    print(C.pivot(index="k", columns="partition", values="max_r").to_string())
    print({p: (int(R[R.partition == p].G.iloc[0]), int(R[R.partition == p].n_attackable.iloc[0])) for p in PARTITIONS})


if __name__ == "__main__":
    main()
