"""Choose the partition and keep size on the VALIDATION split (REVISION_PLAN 2b; rule in REVISION_LOG 2-3).

    python tools/grouping_select.py [--out results_grouping_val]

Trains one AblationNet per configuration on the training split (30K subset, random split seed 0, quick-preset
budgets) and evaluates it on the validation split only. The test split is never transformed or used.
Writes <out>/val_table.csv (config x edit: r needed, certified detection), <out>/val_configs.csv (clean metrics,
score, eligibility), <out>/view_rates.csv (per-view vote rates), <out>/selection.json.
"""
import argparse, json, os, sys, time, zlib
import numpy as np
import pandas as pd
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.certify import ablation_certify, ablation_certify_exact, ablation_view_votes, ceiling_r, votes_from_views  # noqa
from malcert.config import get_config                                    # noqa: E402
from malcert.data import EDIT_SCOPE, Preprocessor, load_subset, split_indices   # noqa: E402
from malcert.models import AblationNet                                   # noqa: E402
from malcert.partitions import attackable, partition                    # noqa: E402
from malcert.train import fit                                            # noqa: E402

CONFIGS = [("ember", 1), ("ember", 2), ("ember", 3), ("aligned4", 1), ("aligned5", 1), ("aligned5", 2),
           ("aligned7", 1), ("aligned7", 2), ("aligned7", 3)]
EDITS = [e for e, s in EDIT_SCOPE.items() if s == "in"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results_grouping_val")
    a = ap.parse_args()
    os.chdir(ROOT)
    os.makedirs(a.out, exist_ok=True)
    cfg = get_config("quick")
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=0)
    pp = Preprocessor().fit(data["X"][sp["tr"]])
    T = lambda v, dt=torch.float32: torch.as_tensor(v, dtype=dt, device=dev)
    Xtr, ytr = T(pp.transform(data["X"][sp["tr"]])), T(data["y"][sp["tr"]], torch.long)
    Xva, yva = T(pp.transform(data["X"][sp["va"]])), T(data["y"][sp["va"]], torch.long)
    yv = data["y"][sp["va"]]
    del data                                                         # the test split is never transformed
    fp = pd.read_csv(os.path.join("ps_results", "grouping_footprint.csv"))
    rows, conf, rates = [], [], []
    for p, k in CONFIGS:
        gid, names = partition(p)
        G, att = len(names), attackable(gid)
        torch.manual_seed(zlib.crc32(f"{p}|{k}".encode()))
        t0 = time.time()
        net = fit(AblationNet(Xtr.shape[1], G, gid, cfg.hidden).to(dev), Xtr, ytr, cfg, "ablation", k=k, seed=0,
                  log=lambda m: None)
        vm = ablation_view_votes(net, Xva, k)
        votes = votes_from_views(vm)
        pred = (votes[:, 1] >= votes[:, 0]).long().cpu().numpy()
        cmax = ceiling_r(G, k)
        ex = ablation_certify_exact(vm, yva, net.subsets(k), att, len(att))
        bd = ablation_certify(votes, yva, G, k, len(att))
        mal = yv == 1
        cs = []
        for e in EDITS:
            r = int(fp[(fp.partition == p) & (fp.edit == e)].r_needed.iloc[0])
            c = float(ex[mal, r].mean()) if r <= min(cmax, len(att)) else 0.0
            cb = float(bd[mal, r].mean()) if r <= min(cmax, len(att)) else 0.0
            cs.append(c)
            rows.append(dict(partition=p, k=k, edit=e, r_needed=r, certifiable=r <= cmax, cert_exact=c, cert_bound=cb))
        acc = float((pred == yv).mean())
        conf.append(dict(partition=p, k=k, G=G, attackable=len(att), views=len(net.subsets(k)), ceiling=cmax,
                         val_acc=acc, val_tpr=float(pred[mal].mean()), val_fpr=float(pred[~mal].mean()),
                         score=float(np.mean(cs)), n_types_certified=int(sum(c > 0 for c in cs)),
                         exact_minus_bound_max=max(float(ex[mal, r].mean() - bd[mal, r].mean()) for r in range(len(att) + 1)),
                         train_seconds=round(time.time() - t0, 1)))
        vmn = vm.cpu().numpy()
        for i, s in enumerate(net.subsets(k)):
            rates.append(dict(partition=p, k=k, view="+".join(names[g] for g in s),
                              attackable=any(g in att for g in s),
                              malware_vote_rate_on_malware=float(vmn[mal, i].mean()),
                              benign_vote_rate_on_benign=float(1 - vmn[~mal, i].mean())))
        print(f"{p} k={k}: acc {100 * acc:.2f}  score {100 * conf[-1]['score']:.1f}  ({conf[-1]['train_seconds']}s)", flush=True)
    C = pd.DataFrame(conf)
    best = C.val_acc.max()
    C["eligible"] = C.val_acc >= best - 0.01
    E = C[C.eligible].sort_values(["score", "views", "val_acc"], ascending=[False, True, False])
    top = E.score.max()
    pick = E[E.score >= top - 0.005].sort_values(["views", "val_acc"], ascending=[True, False]).iloc[0]
    pd.DataFrame(rows).to_csv(os.path.join(a.out, "val_table.csv"), index=False)
    C.to_csv(os.path.join(a.out, "val_configs.csv"), index=False)
    pd.DataFrame(rates).to_csv(os.path.join(a.out, "view_rates.csv"), index=False)
    json.dump(dict(selected=dict(partition=pick.partition, k=int(pick.k)), rule="REVISION_LOG 2-3",
                   best_val_acc=float(best), n_val=int(len(yv)), n_val_malware=int((yv == 1).sum())),
              open(os.path.join(a.out, "selection.json"), "w"), indent=1)
    print("selected:", pick.partition, int(pick.k))


if __name__ == "__main__":
    main()
