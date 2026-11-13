"""Run every experiment in the paper and save results/results.json + per-sample arrays.

    python run_all.py --preset quick      # ~1 h on CPU, 1 seed  (debug / first look)
    python run_all.py --preset full       # paper numbers, 3 seeds (GPU recommended)
    python run_all.py --preset full --blocks clean,ablation,certified   # only some experiment blocks

Resume: results are saved after every block. Re-running the same command continues where an
interrupted run stopped; seeds and blocks already in <out_dir>/results.json are skipped.
"""
import argparse, glob, hashlib, itertools, json, os, platform, shutil, subprocess, sys, time
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score, f1_score

from malcert.config import get_config
from malcert.data import (load_subset, load_full, split_indices, Preprocessor, threat_masks, group_ids,
                          GROUP_NAMES, attackable_groups, FAMILIES, slog1p_)
from malcert.models import (MLP, AblationNet, RandomAblationMLP, ibp, crown, input_box, family_box,
                            load_families)
from malcert.attacks import Constraints, pgd, group_transplant
from malcert.certify import (ablation_votes, ablation_certify, ablation_certify_exact, ablation_view_votes,
                             ceiling_r, smooth_certify, votes_from_views)
from malcert.partitions import attackable, partition
from malcert.train import fit

ROOT = os.path.dirname(os.path.abspath(__file__))

# Experiment blocks, in execution order, and the results.json keys each one writes.
# A block counts as done for a seed when all of its keys are present.
BLOCKS = ("clean", "attacks", "ablation", "smoothing", "certified")
BLOCK_KEYS = {"clean": ("lightgbm", "lightgbm_mono", "mlp"), "attacks": ("pgd_at", "attacks"),
              "ablation": ("ablation",), "smoothing": ("smoothing",),
              "certified": ("certified_training",)}


def done_blocks(R):
    return [b for b in BLOCKS if all(k in R for k in BLOCK_KEYS[b])]


def block_seed(seed, block):
    """Seed of the torch generators at the start of a block. Reseeding per block makes a block's
    result independent of which other blocks ran before it (they all share torch's global RNG)."""
    return 1_000_003 * seed + BLOCKS.index(block)


# ------------------------------------ provenance --------------------------------------
def git_commit(root=ROOT):
    """Current commit hash, read from .git directly so it works without git on PATH.
    In a linked worktree .git is a file pointing to the real git directory."""
    try:
        gd = os.path.join(root, ".git")
        common = gd
        if os.path.isfile(gd):
            gd = open(gd).read().strip().split("gitdir: ", 1)[1]
            gd = gd if os.path.isabs(gd) else os.path.join(root, gd)
            cd = os.path.join(gd, "commondir")
            common = os.path.normpath(os.path.join(gd, open(cd).read().strip())) if os.path.exists(cd) else gd
        head = open(os.path.join(gd, "HEAD")).read().strip()
        if not head.startswith("ref: "):
            return head
        ref = head[5:]
        for base in (gd, common):
            p = os.path.join(base, *ref.split("/"))
            if os.path.exists(p):
                return open(p).read().strip()
        for line in open(os.path.join(common, "packed-refs")):
            if line.strip().endswith(" " + ref):
                return line.split()[0]
    except (OSError, IndexError):
        pass
    return None


def git_dirty(root=ROOT):
    """True if tracked files differ from the commit; None if git cannot be run."""
    exe = os.environ.get("GIT_EXE") or shutil.which("git")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-C", root, "status", "--porcelain", "--untracked-files=no"],
                             capture_output=True, text=True, timeout=30)
        return bool(out.stdout.strip()) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def code_fingerprint(root=ROOT):
    """SHA-256 over run_all.py and malcert/*.py (line endings normalised). Unlike the commit hash
    it also changes with uncommitted edits, so it identifies the code that produced a result."""
    h = hashlib.sha256()
    for f in ["run_all.py"] + sorted(glob.glob(os.path.join(root, "malcert", "*.py"))):
        f = f if os.path.isabs(f) else os.path.join(root, f)
        h.update(os.path.basename(f).encode())
        h.update(open(f, "rb").read().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def provenance(dev, blocks, legacy_rng):
    import lightgbm, pandas, scipy, sklearn
    cuda = dev.type == "cuda"
    return dict(started=time.strftime("%Y-%m-%d %H:%M:%S"), argv=sys.argv[1:], blocks=list(blocks),
                legacy_rng=bool(legacy_rng), git_commit=git_commit(), git_dirty=git_dirty(),
                code_sha256=code_fingerprint(), python=platform.python_version(),
                platform=platform.platform(),
                packages=dict(torch=torch.__version__, numpy=np.__version__, pandas=pandas.__version__,
                              scipy=scipy.__version__, scikit_learn=sklearn.__version__,
                              lightgbm=lightgbm.__version__),
                device=str(dev), device_name=torch.cuda.get_device_name(0) if cuda else platform.processor(),
                cuda=torch.version.cuda if cuda else None)


# -------------------------------------- helpers ---------------------------------------
def metrics(y, pred, score=None):
    y, pred = np.asarray(y), np.asarray(pred)
    out = dict(acc=float((y == pred).mean()), f1=float(f1_score(y, pred)),
               tpr=float((pred[y == 1] == 1).mean()), fpr=float((pred[y == 0] == 1).mean()))
    if score is not None:
        out["auc"] = float(roc_auc_score(y, score))
    return out


@torch.no_grad()
def predict(model, X, bs=4096):
    P = torch.cat([F.softmax(model(X[a:a + bs]), 1)[:, 1] for a in range(0, len(X), bs)])
    return P.cpu().numpy()


def attack_curve(model, Xm, ym, cfg, C):
    """Robust detection rate (TPR) of malware under FGSM / PGD for each eps."""
    out = {}
    for name, steps in (("fgsm", 1), ("pgd", cfg.pgd_steps)):
        out[name] = []
        for eps in cfg.eps_list:
            det = []
            for a in range(0, len(Xm), 500):
                _, fooled = pgd(model, Xm[a:a + 500], ym[a:a + 500], eps, C, steps=steps,
                                restarts=cfg.pgd_restarts)
                det.append((~fooled).cpu().numpy())
            out[name].append(float(np.concatenate(det).mean()))
    return out


def verify(model, X, y, eps, C, bs=1024):
    """Sound certificate: margin lower bound > 0 under max(IBP, CROWN)."""
    res = []
    for a in range(0, len(X), bs):
        x, t = X[a:a + bs], y[a:a + bs]
        with torch.no_grad():
            lo, hi = input_box(x, eps, C.mask, C.mono, C.zlo, C.zhi)
            lb_i, pre = ibp(model, lo, hi, t)
            lb_c = crown(model, lo, hi, t, pre)
        res.append((torch.maximum(lb_i, lb_c) > 0).cpu().numpy())
    return np.concatenate(res)


def fit_lgbm_views(Xraw, y, gid, k, n_estimators, num_leaves, seed):
    """One LightGBM per view (kept-group subset of size k), trained on the raw features of the kept groups."""
    import lightgbm as lgb
    subsets = [tuple(s) for s in itertools.combinations(range(int(gid.max()) + 1), k)]
    views = []
    for s in subsets:
        cols = np.where(np.isin(gid, s))[0]
        g = lgb.LGBMClassifier(n_estimators=n_estimators, num_leaves=num_leaves, learning_rate=0.05,
                               random_state=seed, verbose=-1)
        g.fit(Xraw[:, cols], y)
        views.append((cols, g))
    return subsets, views


def lgbm_view_votes(views, A):
    """(N, V) bool malware votes of per-view LightGBMs on raw features A."""
    A = np.asarray(A)
    return torch.as_tensor(np.stack([g.predict_proba(A[:, c])[:, 1] >= 0.5 for c, g in views], 1))


def family_verify(model, X, y, lo_z, hi_z, t, zlo, zhi, bs=1024):
    """Certified over the edit-family set T_f(t) (2h): margin lower bound max(IBP, CROWN) > 0."""
    res = []
    for a in range(0, len(X), bs):
        x, tt = X[a:a + bs], y[a:a + bs]
        with torch.no_grad():
            lo, hi = family_box(x, t, lo_z, hi_z, zlo, zhi)
            lb_i, pre = ibp(model, lo, hi, tt)
            lb_c = crown(model, lo, hi, tt, pre)
        res.append((torch.maximum(lb_i, lb_c) > 0).cpu().numpy())
    return np.concatenate(res)


def family_report(model, X, y_np, fams, scales, zlo, zhi, dev):
    """Certified detection of malware over T_f(t), per family and for all four families at once."""
    yt = torch.as_tensor(y_np, device=dev)
    mal = y_np == 1
    out, allc = {}, {}
    for f, (lo_z, hi_z) in fams.items():
        out[f] = []
        for t in scales:
            c = family_verify(model, X, yt, lo_z, hi_z, t, zlo, zhi)
            out[f].append(float(c[mal].mean()))
            allc[t] = c if t not in allc else (allc[t] & c)
    out["all_families"] = [float(allc[t][mal].mean()) for t in scales]
    out["mean_over_families_t1"] = float(np.mean([out[f][list(scales).index(1.0)] for f in fams]))
    return out


def corpus_soundness(model, pp, fams_slog, fams_z, scales, zlo, zhi, dev):
    """2h.9: eval-half benign corpus files whose real edit lies inside T_f(t): if the original is certified
    benign over T_f(t), the edited file must still be classified benign. Returns the number of violations
    (must be 0) and the number of (file, family, t) cases checked."""
    F = np.load(os.path.join(ROOT, "ps_results", "features.npz"))
    halves = dict(np.loadtxt(os.path.join(ROOT, "ps_results", "corpus_halves.csv"), delimiter=",", dtype=str,
                             skiprows=1))
    X, fn, ed = F["X"], F["fname"], F["edit"]
    orig = {f: X[i] for i, f in enumerate(fn) if ed[i] == "orig"}
    viol, checked = 0, 0
    for f, edits in FAMILIES.items():
        rows = [i for i in range(len(X)) if ed[i] in edits and halves.get(str(fn[i])) == "eval"]
        if not rows:
            continue
        Xo = np.stack([orig[fn[i]] for i in rows]); Xe = X[rows]
        D = slog1p_(Xe.copy()) - slog1p_(Xo.copy())
        lo_s, hi_s, sup = fams_slog[f]
        zo = torch.as_tensor(pp.transform(Xo), device=dev); ze = torch.as_tensor(pp.transform(Xe), device=dev)
        with torch.no_grad():
            pred_e = model(ze).argmax(1).cpu().numpy()
        for t in scales:
            ins = (~(D[:, ~sup] != 0).any(1)) & ((D[:, sup] >= t * lo_s[sup] - 1e-9) &
                                                (D[:, sup] <= t * hi_s[sup] + 1e-9)).all(1)   # as edit_families.inside
            if not ins.any():
                continue
            c = family_verify(model, zo[ins], torch.zeros(int(ins.sum()), dtype=torch.long, device=dev),
                              fams_z[f][0], fams_z[f][1], t, zlo, zhi)
            viol += int((c & (pred_e[ins] != 0)).sum())
            checked += int(ins.sum())
    return viol, checked


# ------------------------------------- one seed ---------------------------------------
def run_seed(cfg, seed, dev, log, todo, R, S, run_id, legacy_rng=False, save=lambda: None):
    """Run the blocks in `todo` for one seed, adding to R (scalar results) and S (per-sample
    arrays), which may already hold other blocks of this seed. save() is called after each block."""
    torch.manual_seed(seed); np.random.seed(seed)
    # 30K subset (same for every seed), or all of BODMAS (3e full-data check, memory-lean: X is the only full copy)
    data = load_full(cfg) if cfg.full_data else load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=seed)
    if cfg.eval_split == "val":                    # pilots before Stage 3: evaluate on validation, never on test
        sp = dict(tr=sp["tr"], va=sp["va"], te=sp["va"])
    pp = Preprocessor().fit_rows(data["X"], sp["tr"]) if cfg.full_data else Preprocessor().fit(data["X"][sp["tr"]])
    T = lambda a, dt=torch.float32: torch.as_tensor(a, dtype=dt, device=dev)

    def to_dev(idx, chunk=8192):
        """Standardised rows idx as one tensor on the device, transformed in chunks (no full-size host copy)."""
        out = torch.empty(len(idx), data["X"].shape[1], dtype=torch.float32, device=dev)
        for a in range(0, len(idx), chunk):
            out[a:a + chunk] = T(pp.transform(data["X"][idx[a:a + chunk]]))
        return out

    Xtr, Xva, Xte = (to_dev(sp[k]) for k in ("tr", "va", "te"))
    ytr, yva, yte = (T(data["y"][sp[k]], torch.long) for k in ("tr", "va", "te"))
    yte_np = data["y"][sp["te"]]
    S["y"], S["category"] = yte_np, np.asarray(data["category"][sp["te"]], dtype=str)
    S["val_y"], S["val_category"] = data["y"][sp["va"]], np.asarray(data["category"][sp["va"]], dtype=str)
    ts = data["timestamp"][sp["te"]]
    S["month"] = np.asarray(ts.strftime("%Y-%m").fillna("unknown"), dtype=str)          # 3c: test month
    # 3b: L2 distance of every test sample to its nearest training sample (standardised; near-twin <= 0.1)
    nn = []
    with torch.no_grad():
        for a in range(0, len(Xte), 256):
            nn.append(torch.cat([torch.cdist(Xte[a:a + 256], Xtr[b:b + 16384]).min(1).values[:, None]
                                 for b in range(0, len(Xtr), 16384)], 1).min(1).values.cpu())
    S["nn_dist"] = torch.cat(nn).numpy()
    mutable, monotone = threat_masks()
    gid = group_ids()
    zlo, zhi = pp.bounds()                         # natural bounds per feature, not the training range
    Ccon = Constraints(mutable, monotone, zlo, zhi, dev, constrained=True)
    Cunc = Constraints(mutable, monotone, zlo, zhi, dev, constrained=False)
    d = Xtr.shape[1]
    R["data"] = dict(n_train=len(ytr), n_val=len(yva), n_test=len(yte), eval_split=cfg.eval_split,
                     n_mutable=int(mutable.sum()), n_monotone=int(monotone.sum()),
                     attackable_groups=[GROUP_NAMES[g] for g in attackable_groups()],
                     n_malware=int(data["y"].sum()), n_benign=int((data["y"] == 0).sum()),
                     n_categories=int(len(set(data["category"])) - 1),
                     n_families=int(len(set(data["family"])) - 1),
                     categories={c: int((data["category"] == c).sum()) for c in sorted(set(data["category"]))})
    R.setdefault("timing", {}); R.setdefault("runs", {})
    log(f"seed {seed}: train {len(ytr)} / val {len(yva)} / test {len(yte)}; mutable dims {mutable.sum()}"
        f"; blocks {','.join(todo)}")
    mal = torch.where(yte == 1)[0][:cfg.n_attack_points]      # malware test points that are attacked
    Xm, ym = Xte[mal], yte[mal]
    state = {}

    def reseed(block):
        if not legacy_rng:
            torch.manual_seed(block_seed(seed, block))

    def get_std():
        """Standard MLP: reported in 'clean', attacked in 'attacks' and 'ablation'. It is always
        trained from the 'clean' seed, so it is the same network whichever blocks are run."""
        if "std" not in state:
            reseed("clean")
            state["std"] = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "clean", seed=seed, log=log)
        return state["std"]

    def finish(block, t0):
        R["timing"][block] = round(time.time() - t0, 1)
        R["runs"][block] = run_id
        log(f"  [block {block} done in {R['timing'][block]:.0f}s]")
        save()

    # ---- shared by all blocks: the uniform group-transplant attack (2e) and cost records (2f) ----
    R.setdefault("group_attack", {}); R.setdefault("cost", {})
    ugid, unames = partition(cfg.grouping)                  # threat-model groups of the uniform attack table
    ugroups = attackable(ugid)
    gm_idx = torch.where(yte == 1)[0][:cfg.group_attack_points]
    ben_tr = np.where(data["y"][sp["tr"]] == 0)[0]
    gen = torch.Generator().manual_seed(seed)
    donor_idx = [ben_tr[torch.randperm(len(ben_tr), generator=gen)[:cfg.group_attack_donors].numpy()]
                 for _ in range(len(gm_idx))]
    # Models on standardised features are attacked in standardised space; models on raw features (LightGBM)
    # in raw space, with the donors' raw values. (Round-tripping through the standardisation is not exact:
    # an exact 0 comes back as ~1e-8, and LightGBM splits sit exactly at such values.)
    Xtr_raw_np, Xte_raw_np = data["X"][sp["tr"]], data["X"][sp["te"]]
    max_r = lambda groups: min(cfg.group_attack_max_r, len(groups))

    def emp_curve(score_fn, g_ids=None, groups=None, raw=False):
        """Detection (bool) per attacked malware sample and r = 0..max_r under the greedy group transplant."""
        g_ids, groups = (ugid, ugroups) if g_ids is None else (g_ids, groups)
        rows = []
        for j, i in enumerate(gm_idx.tolist()):
            if raw:
                x, donors = torch.as_tensor(Xte_raw_np[i]), torch.as_tensor(Xtr_raw_np[donor_idx[j]])
            else:
                x, donors = Xte[i], Xtr[torch.as_tensor(donor_idx[j], device=dev)]
            det = group_transplant(score_fn, x, donors, g_ids, groups, max_r(groups))
            rows.append(np.cumprod(det).astype(bool))       # budget r allows any r' <= r
        return np.array(rows)

    def attack_all(name, score_fn, raw=False):
        R["group_attack"][name] = emp_curve(score_fn, raw=raw).mean(0).tolist()
        log(f"  group-transplant ({cfg.grouping} groups) on {name}: {R['group_attack'][name]}")

    def raw_score(model_proba):
        """score_fn for models trained on raw features (LightGBM): the attack runs in raw space."""
        return lambda A: torch.as_tensor(model_proba(A.detach().cpu().numpy()))

    def cost(name, train_s, cert_s=None, n=None, passes=None):
        R["cost"][name] = dict(train_seconds=round(train_s, 1),
                               cert_ms_per_sample=None if cert_s is None else round(1000 * cert_s / n, 3),
                               forward_passes_per_sample=passes)

    # ---------------- baselines ----------------
    if "clean" in todo:
        t0 = time.time()
        reseed("clean")
        import lightgbm as lgb
        x0 = data["X"][sp["tr"]][:64]
        assert np.allclose(pp.inverse(pp.transform(x0)), x0, rtol=1e-3, atol=1e-3)
        for name, extra in (("lightgbm", {}),
                            # Incer et al. (2018): increase-only features may only raise the malware score
                            ("lightgbm_mono", dict(monotone_constraints=[int(v) for v in monotone],
                                                   monotone_constraints_method="basic"))):
            t1 = time.time()
            gbm = lgb.LGBMClassifier(n_estimators=500, num_leaves=64, learning_rate=0.05,
                                     random_state=seed, verbose=-1, **extra)
            gbm.fit(data["X"][sp["tr"]], data["y"][sp["tr"]])
            tr_s = time.time() - t1
            s = gbm.predict_proba(data["X"][sp["te"]])[:, 1]
            R[name] = metrics(yte_np, s >= 0.5, s)
            S["pred_" + name] = (s >= 0.5).astype(np.int8)
            S["val_pred_" + name] = (gbm.predict_proba(data["X"][sp["va"]])[:, 1] >= 0.5).astype(np.int8)
            cost(name, tr_s)
            log(f"  {name} {R[name]}  ({tr_s:.0f}s)")
            attack_all(name, raw_score(lambda A, g=gbm: g.predict_proba(A)[:, 1]), raw=True)
        std = get_std()
        s = predict(std, Xte); R["mlp"] = metrics(yte_np, s >= 0.5, s); log(f"  MLP {R['mlp']}")
        S["p_mlp"] = s
        S["pred_mlp"] = (s >= 0.5).astype(np.int8)
        S["val_pred_mlp"] = (predict(std, Xva) >= 0.5).astype(np.int8)
        attack_all("mlp", lambda Z: torch.as_tensor(predict(std, Z)))
        finish("clean", t0)

    # ---------------- C1: attacks ----------------
    if "attacks" in todo:
        t0 = time.time()
        std = get_std()
        reseed("attacks")
        at = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "pgd", C=Ccon, seed=seed, log=log)
        s = predict(at, Xte); R["pgd_at"] = metrics(yte_np, s >= 0.5, s); log(f"  PGD-AT {R['pgd_at']}")
        R["attacks"] = {}
        for mname, m in (("mlp", std), ("pgd_at", at)):
            R["attacks"][mname] = {"constrained": attack_curve(m, Xm, ym, cfg, Ccon),
                                   "unconstrained": attack_curve(m, Xm, ym, cfg, Cunc)}
            log(f"  attacks on {mname}: {R['attacks'][mname]}")
        attack_all("pgd_at", lambda Z: torch.as_tensor(predict(at, Z)))
        finish("attacks", t0)

    # ---------------- C2a: group-ablation certificates ----------------
    if "ablation" in todo:
        t0 = time.time()
        reseed("ablation")
        R["ablation"] = {}
        import pandas as pd
        fp = pd.read_csv(os.path.join(ROOT, "ps_results", "grouping_footprint.csv"))
        mal_np = yte_np == 1

        def record(name, part, k, vm, views, cert_ex, cert_bd, emp, extra):
            """Results of one group-ablation detector: clean metrics, certificates (exact and 2*Delta bound),
            certified detection per in-scope edit type at the r it needs, per-view vote rates, violations."""
            G = int(views and max(max(s) for s in views) + 1)
            votes = votes_from_views(vm)
            pred = (votes[:, 1] >= votes[:, 0]).long().cpu().numpy()      # ties -> malware
            by_edit = {}
            for row in fp[fp.partition == part].itertuples():
                ok = row.r_needed <= min(ceiling_r(G, k), cert_ex.shape[1] - 1)
                by_edit[row.edit] = dict(r_needed=int(row.r_needed), certifiable=bool(ok),
                                         cert_tpr=float(cert_ex[mal_np, row.r_needed].mean()) if ok else 0.0)
            cert_sub = cert_ex[gm_idx.cpu().numpy()][:, :emp.shape[1]]
            vmn = vm.cpu().numpy()
            R["ablation"][name] = dict(partition=part, k=k, n_subsets=len(views), ceiling_r=ceiling_r(G, k),
                                       clean=metrics(yte_np, pred, (votes[:, 1] / len(views)).cpu().numpy()),
                                       cert_tpr_exact=cert_ex[mal_np].mean(0).tolist(),
                                       cert_acc_exact=cert_ex.mean(0).tolist(),
                                       cert_tpr=cert_bd[mal_np].mean(0).tolist(), cert_by_edit=by_edit,
                                       view_vote_rate_malware=vmn[mal_np].mean(0).tolist(),
                                       view_vote_rate_benign=(1 - vmn[~mal_np]).mean(0).tolist(),
                                       empirical_tpr=emp.mean(0).tolist(),
                                       violations=int((cert_sub & ~emp).sum()), **extra)   # must stay 0
            S[f"abl_{name}_cert_exact"] = cert_ex
            S[f"pred_abl_{name}"] = pred.astype(np.int8)
            log(f"  ablation {name} ({part}, k={k}): acc {R['ablation'][name]['clean']['acc']:.4f} "
                f"cert_exact {[round(v, 4) for v in R['ablation'][name]['cert_tpr_exact']]} "
                f"violations {R['ablation'][name]['violations']}")

        configs = cfg.ablation_configs[:1] if cfg.ablation_only_main else cfg.ablation_configs   # 3e full-data check
        for name, part, k, view_epochs in configs:
            gid_p, names_p = partition(part)
            G, att = len(names_p), attackable(gid_p)
            t1 = time.time()
            net = fit(AblationNet(d, G, gid_p, cfg.hidden).to(dev), Xtr, ytr, cfg, "ablation", k=k, seed=seed, log=log,
                      epochs=view_epochs or cfg.epochs)
            tr_s, t2 = time.time() - t1, time.time()
            vv = votes_from_views(ablation_view_votes(net, Xva, k))
            S[f"val_pred_abl_{name}"] = (vv[:, 1] >= vv[:, 0]).cpu().numpy().astype(np.int8)
            vm = ablation_view_votes(net, Xte, k)
            cert_ex = ablation_certify_exact(vm, yte, net.subsets(k), att, len(att))      # exact (2a)
            cert_s = time.time() - t2
            cert_bd = ablation_certify(votes_from_views(vm), yte, G, k, len(att))         # 2*Delta bound
            n_sub = len(net.subsets(k))
            score = lambda Z, net=net, k=k, n_sub=n_sub: (ablation_votes(net, Z, k)[:, 1] / n_sub).cpu()
            emp = emp_curve(score, gid_p, att)                   # soundness check in the detector's own groups
            record(name, part, k, vm, net.subsets(k), cert_ex, cert_bd, emp,
                   dict(views=["+".join(names_p[g] for g in s) for s in net.subsets(k)]))
            cost("ablation_" + name, tr_s, cert_s, len(Xte), n_sub)
            attack_all("ablation_" + name, score)

        # ---- 2c / 2g: one LightGBM per view, main and second configurations (Theorem 1 only counts votes) ----
        Xtr_raw, Xte_raw = data["X"][sp["tr"]], data["X"][sp["te"]]
        for (name, part, k, _), (n_est, n_leaves) in zip(configs[:2], cfg.lgbm_view_params):
            gid_p, names_p = partition(part)
            att = attackable(gid_p)
            t1 = time.time()
            subsets, views = fit_lgbm_views(Xtr_raw, data["y"][sp["tr"]], gid_p, k, n_est, n_leaves, seed)
            tr_s, t2 = time.time() - t1, time.time()
            vv = votes_from_views(lgbm_view_votes(views, data["X"][sp["va"]]))
            S[f"val_pred_abl_lgbm_{name}"] = (vv[:, 1] >= vv[:, 0]).numpy().astype(np.int8)
            vm = lgbm_view_votes(views, Xte_raw)
            cert_ex = ablation_certify_exact(vm, torch.as_tensor(yte_np), subsets, att, len(att))
            cert_s = time.time() - t2
            cert_bd = ablation_certify(votes_from_views(vm), torch.as_tensor(yte_np), len(names_p), k, len(att))
            score = raw_score(lambda A, views=views: lgbm_view_votes(views, A).float().mean(1).numpy())
            emp = emp_curve(score, gid_p, att, raw=True)
            record("lgbm_" + name, part, k, vm, subsets, cert_ex, cert_bd, emp,
                   dict(trees_per_view=n_est, leaves=n_leaves))
            cost("ablation_lgbm_" + name, tr_s, cert_s, len(Xte), len(subsets))
            attack_all("ablation_lgbm_" + name, score, raw=True)
        finish("ablation", t0)

    # ---------------- C2b: randomized smoothing ----------------
    if "smoothing" in todo:
        t0 = time.time()
        reseed("smoothing")
        R["smoothing"] = {}
        # 3d: isotropic noise only (subspace variant dropped, Am1); n_cert_points = 0 means every test point
        pts = torch.arange(len(Xte) if cfg.n_cert_points == 0 else min(cfg.n_cert_points, len(Xte)), device=dev)
        masks = {"isotropic": torch.ones(d, device=dev)}
        for sigma in cfg.sigmas:
            for vname, nm in masks.items():
                m = fit(MLP(d, cfg.hidden).to(dev), Xtr, ytr, cfg, "gauss", sigma=sigma, noise_mask=nm,
                        seed=seed, log=log)
                pr, rad = smooth_certify(m, Xte[pts], yte[pts], sigma, nm, cfg.n0, cfg.n_cert, cfg.alpha)
                yp = yte_np[:len(pts)]
                key = f"{vname}_{sigma}"
                R["smoothing"][key] = dict(sigma=sigma, variant=vname,
                                           clean_acc=float((pr == yp).mean()),
                                           abstain=float((pr == -1).mean()),
                                           tpr=float((pr[yp == 1] == 1).mean()))
                S[f"rs_{key}_pred"], S[f"rs_{key}_rad"] = pr, rad
                log(f"  smoothing {key}: {R['smoothing'][key]}")
        S["rs_y"] = yte_np[:len(pts)]

        # ---- 2e: re-implementation of Giri et al. (2026): random group ablation (EMBER groups, each removed
        # with probability giri_drop) + Gaussian noise, both in training and in CERTIFY; L2 radius ----
        t1 = time.time()
        gm = fit(RandomAblationMLP(d, group_ids(), cfg.giri_drop, cfg.hidden).to(dev), Xtr, ytr, cfg, "gauss",
                 sigma=cfg.giri_sigma, noise_mask=torch.ones(d, device=dev), seed=seed, log=log)
        tr_s, t2 = time.time() - t1, time.time()
        pr, rad = smooth_certify(gm, Xte[pts], yte[pts], cfg.giri_sigma, torch.ones(d, device=dev),
                                 cfg.n0, cfg.n_cert, cfg.alpha)
        cert_s = time.time() - t2
        yp = yte_np[:len(pts)]
        R["smoothing"]["giri_reimpl"] = dict(sigma=cfg.giri_sigma, drop=cfg.giri_drop, variant="giri_reimpl",
                                             clean_acc=float((pr == yp).mean()), abstain=float((pr == -1).mean()),
                                             tpr=float((pr[yp == 1] == 1).mean()))
        S["rs_giri_reimpl_pred"], S["rs_giri_reimpl_rad"] = pr, rad
        cost("giri_reimpl", tr_s, cert_s, len(pts), cfg.n0 + cfg.n_cert)
        log(f"  giri_reimpl: {R['smoothing']['giri_reimpl']}")

        @torch.no_grad()
        def giri_score(Z, n=100):                         # smoothed malware vote share, n noisy samples per row
            out = []
            for z in Z:
                zz = z[None] + cfg.giri_sigma * torch.randn(n, d, device=dev)
                out.append(gm(zz).argmax(1).float().mean())
            return torch.stack(out).cpu()
        attack_all("giri_reimpl", giri_score)
        finish("smoothing", t0)

    # ---------------- C3: certified training ----------------
    if "certified" in todo:
        t0 = time.time()
        reseed("certified")
        R["certified_training"] = {}
        box = lambda C, e: dict(eps=e, mask=C.mask, mono=C.mono, zlo=C.zlo, zhi=C.zhi, asym=False)
        fams = load_families(pp.sd, dev)                                  # T_f in standardised units (2h)
        E = np.load(os.path.join(ROOT, "ps_results", "edit_families.npz"))
        fams_slog = {f: (E[f + "_lo"], E[f + "_hi"], E[f + "_support"]) for f in FAMILIES}
        # 2d / 2h: standard, PGD-AT, CROWN-IBP on the constrained box (ablation of C3), on the uniform ball, and
        # edit-aware CROWN-IBP over the four family sets (C3). All certified on both L-inf boxes and on T_f(t).
        variants = {
            "standard": dict(mode="clean"),
            "pgd_at": dict(mode="pgd", C=Ccon),
            "crownibp": dict(mode="crownibp", cert=box(Ccon, cfg.box_train_eps)),
            "crownibp_unc": dict(mode="crownibp", cert=box(Cunc, cfg.unc_train_eps)),
            "crownibp_edit": dict(mode="crownibp", cert=dict(families=fams, t_train=cfg.edit_t_train, agg=cfg.edit_agg,
                                                             zlo=Ccon.zlo, zhi=Ccon.zhi)),
        }
        for vname, kw in variants.items():
            ep = cfg.ibp_epochs if "ibp" in vname else cfg.epochs
            t1 = time.time()
            m = fit(MLP(d, cfg.ibp_hidden).to(dev), Xtr, ytr, cfg, epochs=ep, seed=seed, log=log, **kw)
            tr_s = time.time() - t1
            s = predict(m, Xte)
            row = dict(clean=metrics(yte_np, s >= 0.5, s), cert_tpr=[], cert_acc=[], cert_tpr_unconstrained=[],
                       pgd_tpr=[], violations=0)
            t2 = time.time()
            verify(m, Xte, yte, cfg.ibp_train_eps, Ccon)
            cost("ct_" + vname, tr_s, time.time() - t2, len(Xte), None)
            attack_all("ct_" + vname, lambda Z, m=m: torch.as_tensor(predict(m, Z)))
            for eps in cfg.cert_eps_list:
                c = verify(m, Xte, yte, eps, Ccon)
                cu = verify(m, Xte, yte, eps, Cunc)
                row["cert_tpr"].append(float(c[yte_np == 1].mean()))
                row["cert_acc"].append(float(c.mean()))
                row["cert_tpr_unconstrained"].append(float(cu[yte_np == 1].mean()))
                _, fooled = pgd(m, Xm, ym, eps, Ccon, steps=cfg.pgd_steps)
                fooled = fooled.cpu().numpy()
                row["pgd_tpr"].append(float((~fooled).mean()))
                row["violations"] += int((c[mal.cpu().numpy()] & fooled).sum())   # must stay 0
                if abs(eps - cfg.ibp_train_eps) < 1e-12:
                    S[f"ct_{vname}_cert"] = c
            S[f"pred_ct_{vname}"] = (s >= 0.5).astype(np.int8)
            for f_, (lo_z, hi_z) in fams.items():                         # per-sample family certificates at t = 1
                S[f"ct_{vname}_famcert_t1_{f_}"] = family_verify(m, Xte, yte, lo_z, hi_z, 1.0, Ccon.zlo, Ccon.zhi)
            row["family_cert"] = family_report(m, Xte, yte_np, fams, cfg.family_scales, Ccon.zlo, Ccon.zhi, dev)
            row["family_scales"] = list(cfg.family_scales)
            row["corpus_violations"], row["corpus_checked"] = corpus_soundness(m, pp, fams_slog, fams,
                                                                               cfg.family_scales, Ccon.zlo, Ccon.zhi, dev)
            R["certified_training"][vname] = row
            log(f"  certified training {vname}: {row}")
        finish("certified", t0)
    return R, S


# --------------------------------------- main -----------------------------------------
def write_atomic(path, writer, mode="w"):
    """Write to a temporary file, then rename: an interruption cannot leave a half-written file."""
    tmp = path + ".tmp"
    with open(tmp, mode) as f:
        writer(f)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", default="quick", choices=["quick", "full"])
    ap.add_argument("--data_dir", default="data")
    ap.add_argument("--out_dir", default="results")
    ap.add_argument("--split", default="random", choices=["random", "family", "temporal", "cutoff"])
    ap.add_argument("--cutoff", default="2019-12", help="with --split cutoff: last month of the training period")
    ap.add_argument("--seeds", default=None, help="comma-separated seeds, overriding the preset (e.g. 0,1,2)")
    ap.add_argument("--full_data", action="store_true", help="3e: all of BODMAS, memory-lean")
    ap.add_argument("--ablation_only_main", action="store_true", help="3e: only the main group-ablation configuration")
    ap.add_argument("--eval_split", default="test", choices=["test", "val"],
                    help="val: evaluate on the validation split (pilots before Stage 3)")
    ap.add_argument("--blocks", default="all",
                    help="comma-separated experiment blocks to run: " + ",".join(BLOCKS) + " (default: all)")
    ap.add_argument("--legacy_rng", action="store_true",
                    help="do not reseed per block (reproduces draft-v1 runs; needs all blocks)")
    ap.add_argument("--mix_code", action="store_true",
                    help="allow resuming into results produced by different code (not for paper numbers)")
    a = ap.parse_args()
    blocks = list(BLOCKS) if a.blocks == "all" else [b.strip() for b in a.blocks.split(",") if b.strip()]
    bad = [b for b in blocks if b not in BLOCKS]
    if bad:
        ap.error(f"unknown block(s) {bad}; choose from {', '.join(BLOCKS)}")
    blocks = [b for b in BLOCKS if b in blocks]                 # execution order
    if a.legacy_rng and blocks != list(BLOCKS):
        ap.error("--legacy_rng reproduces the draft-v1 random stream only when all blocks run")
    extra = dict(seeds=tuple(int(s) for s in a.seeds.split(","))) if a.seeds else {}
    cfg = get_config(a.preset, out_dir=a.out_dir, split=a.split, eval_split=a.eval_split, cutoff=a.cutoff,
                     full_data=a.full_data, ablation_only_main=a.ablation_only_main, **extra,
                     data_npz=os.path.join(a.data_dir, "bodmas.npz"),
                     meta_csv=os.path.join(a.data_dir, "bodmas_metadata.csv"),
                     cat_csv=os.path.join(a.data_dir, "bodmas_malware_category.csv"))
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu") if cfg.device == "auto" else torch.device(cfg.device)
    os.makedirs(cfg.out_dir, exist_ok=True)
    res_path = os.path.join(cfg.out_dir, "results.json")
    cfg_dict = {k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(cfg).items()}
    prov = provenance(dev, blocks, a.legacy_rng)

    # ---- resume: continue an existing results.json only if it is the same experiment and code ----
    if os.path.exists(res_path):
        allR = json.load(open(res_path))
        diff = [k for k in cfg_dict if k not in ("seeds", "out_dir", "device") and allR["config"].get(k) != cfg_dict[k]]
        if diff:
            raise SystemExit(f"{res_path} was produced with a different configuration ({', '.join(diff)}). "
                             "Use a new --out_dir.")
        old = allR.get("provenance", [])
        same_code = bool(old) and all(p.get("code_sha256") == prov["code_sha256"] and
                                      bool(p.get("legacy_rng")) == bool(a.legacy_rng) for p in old)
        if not same_code and not a.mix_code:
            raise SystemExit(f"{res_path} was produced by different code or random-stream settings. Mixing them "
                             "in one file would make the results untraceable: use a new --out_dir "
                             "(or --mix_code for debugging only).")
        allR["config"] = cfg_dict
        allR.setdefault("provenance", []).append(prov)
    else:
        allR = {"config": cfg_dict, "provenance": [prov], "seeds": {}}
    run_id = len(allR["provenance"]) - 1

    logf = open(os.path.join(cfg.out_dir, "log.txt"), "a")

    def log(msg):
        print(msg, flush=True); logf.write(msg + "\n"); logf.flush()

    log(f"=== preset {a.preset} | device {dev} | split {cfg.split} | blocks {','.join(blocks)} | "
        f"commit {(prov['git_commit'] or 'none')[:7]} | {time.ctime()} ===")
    for seed in cfg.seeds:
        key = str(seed)
        R = allR["seeds"].get(key, {})
        todo = [b for b in blocks if b not in done_blocks(R)]
        if not todo:
            log(f"seed {seed}: all requested blocks already in results.json, skipped")
            continue
        npz = os.path.join(cfg.out_dir, f"samples_seed{seed}.npz")
        S = dict(np.load(npz)) if (R and os.path.exists(npz)) else {}

        def save(R=R, S=S, key=key, npz=npz):
            allR["seeds"][key] = R
            write_atomic(npz, lambda f: np.savez_compressed(f, **S), "wb")
            write_atomic(res_path, lambda f: json.dump(allR, f, indent=1))

        run_seed(cfg, seed, dev, log, todo, R, S, run_id, a.legacy_rng, save)
    log("done")       # results were saved after every block; a run that skips everything writes nothing


if __name__ == "__main__":
    main()
