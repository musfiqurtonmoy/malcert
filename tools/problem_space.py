"""Problem-space check, part 2 (REVISION_PLAN Stage 1d-1g): which features do real PE edits change?

Runs in the `malcert` environment, after tools/ps_build.py has written ps_results/features.npz:

    python tools/problem_space.py

Reads   ps_results/features.npz, edits_manifest.csv, corpus_manifest.csv, and BODMAS (training statistics)
Writes  ps_results/edit_map.csv            per edit and variant: groups touched, epsilon needed, inside threat set;
                                           for LIEF edits also the edit's own footprint against the E0 rebuild
        ps_results/eps_coverage.csv        share of in-scope edited files with epsilon needed <= eps (grid)
        ps_results/edit_files.csv          the same per edited file
        ps_results/unit_evidence.csv       per feature unit: which edits change it, did it ever decrease,
                                           and the annotation that follows from the rule below
        ps_results/bodmas_train_stats_seed0.npz   standardisation statistics used here and by the tests
        paper/tables/tab_edit_map.tex, tab_coverage.tex, tab_annotation.tex, tab_annotation_full.tex
        paper/tables/numbers_ps.tex        macros (prefix Ps) for the text

Annotation rule (REVISION_PLAN 1e), applied per feature unit over the IN-SCOPE edits:
    mutable   <=> some in-scope edit changed it in at least one file, or draft v1 already treated it as
                  mutable (kept: removing attacker power needs evidence, absence of evidence is not enough)
    monotone  <=> mutable, a count or size, and it never decreased under any in-scope edit
    immutable <=> otherwise
The frozen annotation in malcert/data.py must equal what this rule gives; the script fails if it does not.
"""
import argparse, csv, os, sys
from collections import OrderedDict

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from malcert.config import get_config                                             # noqa: E402
from malcert.data import (FEATURE_UNITS, GROUP_NAMES, EDIT_SCOPE, DRAFT_V1_IMMUTABLE_GROUPS,                 # noqa: E402
                          MUTABLE_BY_REASONING, NOT_MONOTONE_BY_REASONING, Preprocessor, attackable_groups, group_ids, load_subset,
                          natural_bounds, split_indices, threat_masks, threat_masks_draft_v1, unit_index)

RES = os.path.join(ROOT, "ps_results")
R_CEIL = 4       # largest r any vote-counting certificate can cover with 9 groups (k = 1): 9 - r > r

# code -> (label in tables, technique name for the coverage table, literature keys)
EDITS = OrderedDict([
    ("E1_overlay", ("E1 Overlay append", "Overlay append (padding)", "demetrio2021exemples,anderson2018learning")),
    ("E2_strings", ("E2 String padding", "String padding", "demetrio2021exemples,anderson2018learning")),
    ("E3_section", ("E3 Section add", "Section injection", "demetrio2021exemples,anderson2018learning")),
    ("E4_imports", ("E4 Import add", "Import addition", "anderson2018learning")),
    ("E5_timestamp", ("E5 Timestamp edit", "Timestamp edit", "demetrio2021exemples")),
    ("E6_secnames", ("E6 Section rename", "Section renaming", "demetrio2021exemples,anderson2018learning")),
    ("E7_header", ("E7 Checksum, DOS header", "Checksum and DOS-header edits", "demetrio2021exemples,anderson2018learning")),
    ("E8_strip", ("E8 Strip signature, debug", "Signature and debug stripping", "anderson2018learning")),
    ("E10_hdrfields", ("E10 Version fields, DLL flags", "Header version and DLL-characteristics edits", "")),
    ("E9_upx", ("E9 UPX packing", "Packing (UPX)", "anderson2018learning")),
    ("E0_rebuild", ("E0 LIEF rebuild (control)", "", "")),
])
NUM = {"E0": "Ezero", "E1": "Eone", "E2": "Etwo", "E3": "Ethree", "E4": "Efour", "E5": "Efive", "E6": "Esix",
       "E7": "Eseven", "E8": "Eeight", "E9": "Enine", "E10": "Eten"}
ARCHS = ("PE32+", "PE32")                       # System32 copies / SysWOW64 copies (file name prefix w32__)


def arch_of(name):
    return "PE32" if str(name).startswith("w32__") else "PE32+"
# LIEF-based edits rebuild the whole file. Their control is the same rebuild WITHOUT the edit (E0), so the
# footprint of the edit itself is the difference between the edited file and the rebuilt-only file (1h).
REBUILD_CONTROL = {"E3_section": "plain", "E4_imports": "imports"}
EPS_GRID = [0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100]
NOT_MEASURED = [   # out of scope by design; not measured because they rewrite the code itself
    ("Repacking, crypters", "replace the file by a stub that unpacks the original at run time"),
    ("Code obfuscation, metamorphism", "rewrite the instructions, so every content-derived feature changes"),
    ("Dropper wrapping", "embed the file in a different host program"),
]


def slog(X):
    return np.sign(X) * np.log1p(np.abs(X))


def big(n):
    return f"{int(n):,}".replace(",", "{,}")


def tt(s):
    return "\\texttt{" + s.replace("_", "\\_") + "}"


def bodmas_stats():
    """Standardisation statistics of the BODMAS training split (seed 0), as run_all.py computes them,
    plus the training-set range that draft v1 clipped the box to."""
    cfg = get_config("full")
    data = load_subset(cfg, seed=0)
    sp = split_indices(data, cfg, seed=0)
    pp = Preprocessor().fit(data["X"][sp["tr"]])
    Ztr = (slog(data["X"][sp["tr"]].astype(np.float64)) - pp.mu) / pp.sd
    return pp, Ztr.min(0), Ztr.max(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paper", default=os.path.join(ROOT, "paper"))
    ap.add_argument("--res", nargs="+", default=None,
                    help="results folder(s), seeds pooled: fills the coverage table with the measured certified "
                         "detection of per-view LightGBM under the edit-aligned groupings")
    ap.add_argument("--propose", action="store_true",
                    help="print the annotation the rule gives and do not fail if data.py differs (used once, to freeze it)")
    a = ap.parse_args()
    os.chdir(ROOT)
    F = np.load(os.path.join(RES, "features.npz"))
    X, f_file, f_edit, f_var = F["X"].astype(np.float64), F["fname"], F["edit"], F["variant"]
    corpus = pd.read_csv(os.path.join(RES, "corpus_manifest.csv"))
    man = pd.read_csv(os.path.join(RES, "edits_manifest.csv"))
    assert X.shape[1] == 2381 and np.isfinite(X).all()
    orig = {f: X[i] for i, f in enumerate(f_file) if f_edit[i] == "orig"}
    assert len(orig) == len(corpus)
    rebuilt = {(f, f_var[i]): X[i] for i, f in enumerate(f_file) if f_edit[i] == "E0_rebuild"}

    pp, zmin, zmax = bodmas_stats()
    np.savez_compressed(os.path.join(RES, "bodmas_train_stats_seed0.npz"), mu=pp.mu, sd=pp.sd, zmin=zmin, zmax=zmax)
    Z = lambda A: (slog(A) - pp.mu) / pp.sd
    gid, G = group_ids(), len(GROUP_NAMES)
    uidx = unit_index()
    mut_d, mono_d = threat_masks_draft_v1()
    mut_r, mono_r = threat_masks()
    att_d = [g for g, n in enumerate(GROUP_NAMES) if n not in DRAFT_V1_IMMUTABLE_GROUPS]
    att_r = attackable_groups()
    lo_nat, hi_nat = natural_bounds()
    Xo_all = np.stack(list(orig.values()))
    assert ((Xo_all >= lo_nat) & (Xo_all <= hi_nat)).all(), "an original file violates a natural bound"

    # ---------------- per edited file ----------------
    files, unit_rows = [], []
    for e in EDITS:
        for v in sorted(set(f_var[f_edit == e])):
            idx = np.where((f_edit == e) & (f_var == v))[0]
            O, E = np.stack([orig[f] for f in f_file[idx]]), X[idx]
            Zo, Ze = Z(O), Z(E)
            ch = E != O
            gch = np.stack([ch[:, gid == g].any(1) for g in range(G)], 1)
            # footprint of the edit itself: against the rebuilt-only file for LIEF edits, else against the original
            if e in REBUILD_CONTROL:
                # the control exists for every file whose LIEF edit succeeded (same builder); fail loudly if not
                Bv = np.stack([rebuilt[(f, REBUILD_CONTROL[e])] for f in f_file[idx]])
                own = np.stack([(E != Bv)[:, gid == g].any(1) for g in range(G)], 1)
                reb = np.stack([(Bv != O)[:, gid == g].any(1) for g in range(G)], 1)
            else:
                own, reb = gch, np.zeros_like(gch)
            linf = np.abs(Ze - Zo).max(1)
            nat_ok = ((E >= lo_nat) & (E <= hi_nat)).all(1)
            rng_ok = ((Ze <= np.maximum(zmax, Zo) + 1e-9) & (Ze >= np.minimum(zmin, Zo) - 1e-9)).all(1)
            for j, i in enumerate(idx):
                files.append(dict(
                    file=f_file[i], arch=arch_of(f_file[i]),
                    edit=e, variant=v, scope=EDIT_SCOPE[e], n_groups=int(gch[j].sum()),
                    groups="+".join(GROUP_NAMES[g] for g in range(G) if gch[j, g]),
                    n_features_changed=int(ch[j].sum()), eps_needed=float(linf[j]),
                    n_groups_edit_only=int(own[j].sum()),
                    groups_edit_only="+".join(GROUP_NAMES[g] for g in range(G) if own[j, g]),
                    n_groups_rebuild=int(reb[j].sum()),
                    **{"own_" + GROUP_NAMES[g]: bool(own[j, g]) for g in range(G)},
                    # draft-v1 threat set: its masks, its monotone set, the training-range clip, its 7 groups
                    draft_immutable_changed=bool((ch[j] & ~mut_d).any()),
                    draft_monotone_decreased=bool(((E[j] < O[j]) & mono_d).any()),
                    draft_outside_training_range=not bool(rng_ok[j]),
                    draft_group_inside=not bool(gch[j][[g for g in range(G) if g not in att_d]].any()),
                    # repaired threat set: frozen annotation in data.py, natural bounds, attackable groups
                    repaired_immutable_changed=bool((ch[j] & ~mut_r).any()),
                    repaired_monotone_decreased=bool(((E[j] < O[j]) & mono_r).any()),
                    repaired_outside_natural_bounds=not bool(nat_ok[j]),
                    repaired_group_inside=not bool(gch[j][[g for g in range(G) if g not in att_r]].any()),
                    **{"g_" + GROUP_NAMES[g]: bool(gch[j, g]) for g in range(G)}))
            arch = np.array([arch_of(f) for f in f_file[idx]])
            for ar in ARCHS:
                m = arch == ar
                if not m.any():
                    continue
                for n, s, t, kind in FEATURE_UNITS:
                    unit_rows.append(dict(unit=n, edit=e, variant=v, arch=ar, n=int(m.sum()),
                                          changed=int(ch[m, s:t].any(1).sum()),
                                          decreased=int((E[m, s:t] < O[m, s:t]).any(1).sum()),
                                          increased=int((E[m, s:t] > O[m, s:t]).any(1).sum())))
    D = pd.DataFrame(files)
    D["draft_box_inside"] = ~(D.draft_immutable_changed | D.draft_monotone_decreased | D.draft_outside_training_range)
    D["repaired_box_inside"] = ~(D.repaired_immutable_changed | D.repaired_monotone_decreased
                                 | D.repaired_outside_natural_bounds)
    D.to_csv(os.path.join(RES, "edit_files.csv"), index=False)
    UR = pd.DataFrame(unit_rows)

    # ---------------- edit map ----------------
    def agg(d, e, v, ar="all"):
        row = OrderedDict(edit=e, variant=v, arch=ar, scope=EDIT_SCOPE[e], n_files=len(d),
                          groups_median=float(d.n_groups.median()), groups_max=int(d.n_groups.max()))
        for g in GROUP_NAMES:
            row["share_" + g] = float(d["g_" + g].mean())
        row.update(groups_edit_only_median=float(d.n_groups_edit_only.median()),
                   groups_edit_only_max=int(d.n_groups_edit_only.max()),
                   groups_rebuild_median=float(d.n_groups_rebuild.median()))
        for g in GROUP_NAMES:
            row["own_share_" + g] = float(d["own_" + g].mean())
        row.update(features_changed_median=float(d.n_features_changed.median()),
                   eps_median=float(d.eps_needed.median()), eps_p90=float(d.eps_needed.quantile(0.9)),
                   eps_max=float(d.eps_needed.max()),
                   draft_box_inside=float(d.draft_box_inside.mean()),
                   draft_fail_immutable_changed=float(d.draft_immutable_changed.mean()),
                   draft_fail_monotone_decreased=float(d.draft_monotone_decreased.mean()),
                   draft_fail_outside_training_range=float(d.draft_outside_training_range.mean()),
                   draft_group_inside=float(d.draft_group_inside.mean()),
                   repaired_box_inside=float(d.repaired_box_inside.mean()),
                   repaired_group_inside=float(d.repaired_group_inside.mean()))
        return row
    M = []
    for e in EDITS:
        de = D[D.edit == e]
        if len(de) == 0:
            continue
        M.append(agg(de, e, "all"))
        for v in sorted(set(de.variant)):
            M.append(agg(de[de.variant == v], e, v))
        for ar in ARCHS:                                     # 1i: the same per architecture
            da = de[de.arch == ar]
            if len(da):
                M.append(agg(da, e, "all", ar))
                for v in sorted(set(da.variant)):
                    M.append(agg(da[da.variant == v], e, v, ar))
    M = pd.DataFrame(M)
    M.to_csv(os.path.join(RES, "edit_map.csv"), index=False)
    MA = M[M.arch != "all"]                                  # per-architecture rows
    M = M[M.arch == "all"]
    Mall = M[M.variant == "all"].set_index("edit")

    # ---------------- 1h: share of measured edits inside the L-infinity box, as a function of epsilon ----------------
    Dsc = D[D.scope == "in"]
    cov_rows = []
    for eps in EPS_GRID:
        row = OrderedDict(eps=eps, all_in_scope=float((Dsc.eps_needed <= eps).mean()))
        for e in EDITS:
            if EDIT_SCOPE[e] == "in":
                row[e] = float((Dsc.eps_needed[Dsc.edit == e] <= eps).mean())
        cov_rows.append(row)
    COV = pd.DataFrame(cov_rows)
    COV.to_csv(os.path.join(RES, "eps_coverage.csv"), index=False)

    # ---------------- unit evidence and the annotation the rule gives ----------------
    in_scope = [e for e in EDITS if EDIT_SCOPE[e] == "in"]

    def apply_rule(u, n, kind, draft):
        """The evidence rule on the rows u of one unit. Returns status, observed edits, decreasing edits, all edits."""
        by = u.groupby("edit")[["n", "changed", "decreased", "increased"]].sum()
        ch_by = [e for e in EDITS if e in by.index and by.changed[e] > 0]
        obs = [e for e in ch_by if e in in_scope]
        dec = [e for e in in_scope if e in by.index and by.decreased[e] > 0]
        mutable = bool(obs) or draft != "immutable" or n in MUTABLE_BY_REASONING
        monotone = mutable and kind == "count" and not dec and n not in NOT_MONOTONE_BY_REASONING
        return ("monotone" if monotone else ("mutable" if mutable else "immutable")), obs, dec, ch_by, by

    ev = []
    for n, s, t, kind in FEATURE_UNITS:
        u = UR[UR.unit == n]
        draft = "monotone" if mono_d[s] else ("mutable" if mut_d[s] else "immutable")
        status, obs, dec, ch_by, by = apply_rule(u, n, kind, draft)
        per_arch = {ar: apply_rule(u[u.arch == ar], n, kind, draft)[0] for ar in ARCHS if (u.arch == ar).any()}
        mutable, monotone = status != "immutable", status == "monotone"
        if obs:
            rule = "changed by " + ", ".join(x.split("_")[0] for x in obs)
            if obs == ["E10_hdrfields"]:
                rule += " only (plausibly functionality-preserving, not verified by execution)"
        elif n in MUTABLE_BY_REASONING:
            rule = "conservative, not observed: " + MUTABLE_BY_REASONING[n].split(",")[0]
        elif mutable:
            rule = "conservative, not observed: no in-scope edit changed it; kept mutable as in draft v1"
        else:
            rule = "not changed by any in-scope edit"
        if mutable and kind == "count":
            if monotone:
                rule += "; never decreased"
            elif dec:
                rule += "; decreased under " + ", ".join(x.split("_")[0] for x in dec)
            else:
                rule += ("; not increase-only (conservative, not observed: never decreased, but "
                         + NOT_MONOTONE_BY_REASONING[n].split(",")[0].split(";")[0] + ")")
        frozen = "monotone" if mono_r[s] else ("mutable" if mut_r[s] else "immutable")
        row = OrderedDict(unit=n, start=s, end=t, n_features=t - s, kind=kind, group=uidx[n][3], draft_v1=draft,
                          rule_gives=status, frozen_in_data_py=frozen, rule=rule,
                          rule_on_pe32plus_only=per_arch.get("PE32+", ""), rule_on_pe32_only=per_arch.get("PE32", ""),
                          changed_by_in_scope=" ".join(obs), decreased_by_in_scope=" ".join(dec),
                          changed_by_out_of_scope=" ".join(e for e in ch_by if EDIT_SCOPE[e] == "out"),
                          changed_by_control=" ".join(e for e in ch_by if EDIT_SCOPE[e] == "control"))
        for e in EDITS:
            row["share_" + e] = float(by.changed[e] / by.n[e]) if e in by.index else float("nan")
        ev.append(row)
    EV = pd.DataFrame(ev)
    EV.to_csv(os.path.join(RES, "unit_evidence.csv"), index=False)
    mm = EV[EV.rule_gives != EV.frozen_in_data_py]
    mut_units = EV.unit[EV.rule_gives != "immutable"].tolist()
    mono_units = EV.unit[EV.rule_gives == "monotone"].tolist()
    if a.propose:
        print("MUTABLE_UNITS =", mut_units)
        print("MONOTONE_UNITS =", mono_units)
    elif len(mm):
        raise SystemExit("The annotation frozen in malcert/data.py differs from what the evidence rule gives for: "
                         + ", ".join(f"{r.unit} (rule {r.rule_gives}, frozen {r.frozen_in_data_py})" for r in mm.itertuples())
                         + ". Run with --propose and update data.py, or explain the exception.")

    # ---------------- checks that the repaired threat set contains every in-scope edit ----------------
    Din = D[D.scope == "in"]
    n_out_box, n_out_grp = int((~Din.repaired_box_inside).sum()), int((~Din.repaired_group_inside).sum())
    print(f"in-scope edited files: {len(Din)}; outside the repaired box: {n_out_box}; outside the repaired groups: {n_out_grp}")
    if not a.propose and (n_out_box or n_out_grp):
        raise SystemExit("an in-scope edit falls outside the repaired threat set")

    # ---------------- console summary ----------------
    pd.set_option("display.width", 250); pd.set_option("display.max_columns", 40)
    show = M[M.variant == "all"][["edit", "scope", "n_files", "groups_median", "groups_max", "eps_median", "eps_p90",
                                  "draft_box_inside", "draft_group_inside", "repaired_box_inside",
                                  "repaired_group_inside"]]
    print(show.to_string(index=False, float_format=lambda x: f"{x:.3g}"))
    print("\nshare of files in which each group changes:")
    print(M[M.variant == "all"][["edit"] + ["share_" + g for g in GROUP_NAMES]].to_string(
        index=False, float_format=lambda x: f"{x:.2f}"))
    if len(MA):
        cmp_ = MA[MA.variant == "all"].pivot(index="edit", columns="arch",
                                             values=["n_files", "groups_median", "groups_max", "eps_median"])
        print("\nper architecture (PE32 = SysWOW64 copies, PE32+ = System32 copies):")
        print(cmp_.reindex([e for e in EDITS if e in cmp_.index]).to_string(float_format=lambda x: f"{x:.3g}"))
        da = EV[(EV.rule_on_pe32_only != "") & (EV.rule_on_pe32plus_only != EV.rule_on_pe32_only)]
        print(f"\nunits where the rule gives a different status on PE32 files alone and on PE32+ files alone: {len(da)}")
        if len(da):
            print(da[["unit", "rule_on_pe32plus_only", "rule_on_pe32_only", "rule_gives", "rule"]].to_string(index=False))
    ch_ann = EV[EV.draft_v1 != EV.rule_gives]
    print(f"\nunits whose annotation changes: {len(ch_ann)} of {len(EV)}")
    print(ch_ann[["unit", "n_features", "kind", "draft_v1", "rule_gives", "rule"]].to_string(index=False))
    mut_new = np.zeros(2381, bool); mono_new = np.zeros(2381, bool)
    for r in EV.itertuples():
        mut_new[r.start:r.end] = r.rule_gives != "immutable"; mono_new[r.start:r.end] = r.rule_gives == "monotone"
    att_new = [g for g in range(G) if mut_new[gid == g].any()]
    print(f"\nmutable features: draft {int(mut_d.sum())} -> rule {int(mut_new.sum())}; "
          f"monotone: draft {int(mono_d.sum())} -> rule {int(mono_new.sum())}; "
          f"attackable groups: draft {len(att_d)} -> rule {len(att_new)} "
          f"({', '.join(GROUP_NAMES[g] for g in att_new if g not in att_d) or 'none'} added)")

    # BODMAS provenance check: does any corpus file occur in BODMAS? Then the two extractions can be compared.
    meta = pd.read_csv(get_config("full").meta_csv)
    hit = sorted(set(corpus.sha256) & set(meta["sha"]))
    print(f"\ncorpus files that are also in BODMAS (by SHA-256): {len(hit)}")
    n_same = None
    if hit:
        Xb = np.load(get_config("full").data_npz)["X"]
        pos = {s: i for i, s in enumerate(meta["sha"])}
        same = []
        for s in hit:
            f = corpus.file[corpus.sha256 == s].iloc[0]
            d = np.abs(Xb[pos[s]].astype(np.float64) - orig[f])
            same.append(bool((d == 0).all()))
            print(f"   {f}: features differing from BODMAS: {int((d > 0).sum())}"
                  + ("" if same[-1] else f"  (units: {sorted(set(n for n, s0, t0, _ in FEATURE_UNITS if (d[s0:t0] > 0).any()))})"))
        n_same = sum(same)

    if a.propose:
        return
    write_tables(a.paper, corpus, man, D, M, Mall, EV, mut_d, mono_d, mut_r, mono_r, att_d, att_r, F, len(hit), n_same,
                 MA, a.res)


def pct(x, nd=0):
    return f"{100 * x:.{nd}f}"


def fe(x):
    """Epsilon with two significant digits."""
    return f"{x:.2g}" if x < 100 else f"{x:.0f}"


def write_tables(paper, corpus, man, D, M, Mall, EV, mut_d, mono_d, mut_r, mono_r, att_d, att_r, F, n_bodmas, n_bodmas_same,
                 MA, res):
    tdir = os.path.join(paper, "tables")
    G = len(GROUP_NAMES)
    gid = group_ids()
    short = ["BH", "BE", "Str", "Gen", "Hdr", "Sec", "Imp", "Exp", "DD"]
    mark = lambda s: "$\\bullet$" if s >= 0.995 else ("$\\circ$" if s > 0 else "")

    # ---- Table: edit map ----
    T = ["\\begin{tabular}{lr" + "c" * G + "rrrrrr}", "\\toprule",
         " & & \\multicolumn{%d}{c}{Feature groups changed} & \\multicolumn{2}{c}{Groups} & \\multicolumn{2}{c}{$\\epsilon$ needed}"
         " & \\multicolumn{2}{c}{Inside draft set (\\%%)} \\\\" % G,
         "\\cmidrule(lr){3-%d}\\cmidrule(lr){%d-%d}\\cmidrule(lr){%d-%d}\\cmidrule(lr){%d-%d}" % (
             G + 2, G + 3, G + 4, G + 5, G + 6, G + 7, G + 8),
         "Edit & Files & " + " & ".join(short) + " & med. & max & med. & 90\\% & box & groups \\\\", "\\midrule"]
    for e, (lab, _, _) in EDITS.items():
        if e not in Mall.index:
            continue
        r = Mall.loc[e]
        if e == "E9_upx":
            T.append("\\midrule")
        dag = "$^\\dagger$" if EDIT_SCOPE[e] == "out" else ""      # (no backslash allowed inside an f-string field)
        line = lambda lab_, r_, pre="share_": (
            f"{lab_} & {int(r_.n_files)} & " + " & ".join(mark(r_[pre + g]) for g in GROUP_NAMES)
            + f" & {r_.groups_median:.0f} & {int(r_.groups_max)} & {fe(r_.eps_median)} & {fe(r_.eps_p90)}"
            + f" & {pct(r_.draft_box_inside)} & {pct(r_.draft_group_inside)} \\\\")
        if e == "E0_rebuild":                                       # the two rebuild controls differ: one row each
            for v, vl in (("plain", "E0 LIEF rebuild, no edit (control for E3)"),
                          ("imports", "E0 LIEF import rebuild, no edit (control for E4)")):
                T.append(line(vl, M[(M.edit == e) & (M.variant == v)].iloc[0]))
            continue
        T.append(line(lab + dag, r))
        if e in REBUILD_CONTROL:                                    # 1h: the edit's own footprint, rebuild removed
            T.append("\\quad\\emph{of which the edit itself (vs.\\ E0)} & & "
                     + " & ".join(mark(r['own_share_' + g]) for g in GROUP_NAMES)
                     + f" & {r.groups_edit_only_median:.0f} & {int(r.groups_edit_only_max)} & & & & \\\\")
    T += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_edit_map.tex"), "w").write("\n".join(T))

    # ---- Table: coverage of evasion techniques ----
    # Three levels (REVISION_PLAN 1i.4). "A certificate could apply" is NOT coverage:
    #   (a) inside the threat set AND certified: the measured certified detection at the r the edit needs is > 0
    #   (b) inside the threat set but not certifiable: the edit changes more groups than a vote-counting
    #       certificate can reach, or the measured certified detection at the r it needs is 0
    #   (c) out of scope
    # r needed = the LARGEST number of groups the edit changed in any measured file (every file must be covered).
    # Certified detection: group-ablation certificate with k = 1 (the only keep size that reaches r > 2), from --res.
    # This table is for the 9 EMBER groups; it is filled again after the edit-aligned grouping of Stage 2b.
    # Since Stage 3 (log 4-1): r needed and certified detection come from the edit-aligned groupings of the results
    # (cert_by_edit), for the headline detector (per-view LightGBM, main = aligned5 k=2) and the second operating point
    # (per-view LightGBM, aligned7 k=1), mean over all seeds of the given folders.
    cert, cert_src = None, "not measured yet"
    if res:
        import json
        seeds = [s for f in res for s in json.load(open(os.path.join(f, "results.json")))["seeds"].values()]
        cert = {}
        for cfgname in ("lgbm_main", "lgbm_second"):
            for e in seeds[0]["ablation"][cfgname]["cert_by_edit"]:
                rows = [s["ablation"][cfgname]["cert_by_edit"][e] for s in seeds]
                cert[(cfgname, e)] = (rows[0]["r_needed"], rows[0]["certifiable"], float(np.mean([x["cert_tpr"] for x in rows])))
        cert_src = f"{' + '.join(os.path.basename(os.path.normpath(f)) for f in res)}, {len(seeds)} seed(s)"
    C = ["\\begin{tabular}{lllrrp{0.30\\linewidth}}", "\\toprule",
         "Technique & Measured as & Level & \\multicolumn{2}{c}{$r$ needed / certified detection} & Evidence \\\\",
         " & & & main & second & \\\\", "\\midrule"]
    cov = []
    for e, (lab, tech, _) in EDITS.items():
        if EDIT_SCOPE[e] == "control" or e not in Mall.index:
            continue
        r = Mall.loc[e]
        rmax = int(r.groups_max)
        cells = ["--", "--"]
        if EDIT_SCOPE[e] == "out":
            level = "(c) out of scope"
            evid = (f"{int(r.n_files)} files: changes {r.groups_median:.0f} of {G} EMBER groups (median); "
                    f"{pct(1 - r.repaired_box_inside)}\\% of files change features annotated immutable")
        else:
            assert r.repaired_box_inside == 1 and r.repaired_group_inside == 1, e
            evid = f"{int(r.n_files)} files, all inside the threat set; $\\epsilon$ needed: {fe(r.eps_median)}"
            if cert is None:
                level, cells = "(a) or (b): to be measured", ["to be measured"] * 2
            else:
                got = []
                for i, cfgname in enumerate(("lgbm_main", "lgbm_second")):
                    rn, ok, c = cert[(cfgname, e)]
                    cells[i] = f"{rn} / {100 * c:.1f}\\%" if ok else f"{rn} / none possible"
                    got.append(ok and c > 0)
                level = ("(a) certified, main" if got[0] else "(a) certified, second only" if got[1]
                         else "(b) inside, not certifiable")
        cov.append((tech, e.split("_")[0], level, rmax, cells[0].replace("\\%", "%"), cells[1].replace("\\%", "%")))
        C.append(f"{tech} & {e.split('_')[0]} & {level} & {cells[0]} & {cells[1]} & {evid} \\\\")
    C.append("\\midrule")
    for tech, why in NOT_MEASURED:
        C.append(f"{tech} & not measured & (c) out of scope & -- & -- & {why} \\\\")
    C += ["\\bottomrule", "\\end{tabular}",
          f"% r needed under the edit-aligned groupings; certified detection of per-view LightGBM; source: {cert_src}"]
    open(os.path.join(tdir, "tab_coverage.tex"), "w").write("\n".join(C))
    pd.DataFrame(cov, columns=["technique", "edit", "level", "groups_max_ember", "main", "second"]).assign(
        source=cert_src).to_csv(os.path.join(RES, "coverage.csv"), index=False)

    # ---- Table: edit map per architecture (1i.1) ----
    if len(MA):
        P = ["\\begin{tabular}{lrrrrrrrr}", "\\toprule",
             " & \\multicolumn{4}{c}{PE32+ (64-bit)} & \\multicolumn{4}{c}{PE32 (32-bit)} \\\\",
             "\\cmidrule(lr){2-5}\\cmidrule(lr){6-9}",
             "Edit & Files & Groups med. & max & $\\epsilon$ med. & Files & Groups med. & max & $\\epsilon$ med. \\\\", "\\midrule"]
        for e, (lab, _, _) in EDITS.items():
            cells = []
            for ar in ARCHS:
                q = MA[(MA.edit == e) & (MA.variant == "all") & (MA.arch == ar)]
                cells += ([str(int(q.n_files.iloc[0])), f"{q.groups_median.iloc[0]:.0f}", str(int(q.groups_max.iloc[0])),
                           fe(q.eps_median.iloc[0])] if len(q) else ["--"] * 4)
            if e in Mall.index:
                P.append(f"{lab} & " + " & ".join(cells) + " \\\\")
        P += ["\\bottomrule", "\\end{tabular}"]
        open(os.path.join(tdir, "tab_edit_map_arch.tex"), "w").write("\n".join(P))

    # ---- Table: annotation summary per group ----
    A = ["\\begin{tabular}{lrrrrrll}", "\\toprule",
         " & & \\multicolumn{2}{c}{Mutable} & \\multicolumn{2}{c}{Increase-only} & & \\\\",
         "\\cmidrule(lr){3-4}\\cmidrule(lr){5-6}",
         "Group & Features & draft & repaired & draft & repaired & Attackable & Changed by \\\\", "\\midrule"]
    for g, name in enumerate(GROUP_NAMES):
        m = gid == g
        eds = sorted({x.split("_")[0] for r in EV[EV.group == name].itertuples() for x in r.changed_by_in_scope.split()})
        was, now = g in att_d, g in att_r
        A.append(f"{name} & {int(m.sum())} & {int(mut_d[m].sum())} & {int(mut_r[m].sum())} & {int(mono_d[m].sum())} & "
                 f"{int(mono_r[m].sum())} & {'yes' if now else 'no'}{'' if was == now else ' (was ' + ('yes' if was else 'no') + ')'}"
                 f" & {', '.join(eds) if eds else '--'} \\\\")
    A += ["\\midrule", f"Total & 2{{,}}381 & {big(mut_d.sum())} & {big(mut_r.sum())} & {int(mono_d.sum())} & {int(mono_r.sum())} & "
          f"{len(att_r)} of {G} (was {len(att_d)}) & \\\\", "\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_annotation.tex"), "w").write("\n".join(A))

    # ---- Table: full annotation per unit (appendix) ----
    refs = {e: k for e, (_, _, k) in EDITS.items()}
    L = ["\\begin{tabular}{llrlllp{0.30\\linewidth}l}", "\\toprule",
         "Feature unit & Group & Dim. & Kind & Draft & Repaired & Rule and evidence & Ref. \\\\", "\\midrule"]
    for r in EV.itertuples():
        keys = sorted({k for e in r.changed_by_in_scope.split() for k in refs[e].split(",") if k})
        now = "\\textbf{" + r.frozen_in_data_py + "}" if r.draft_v1 != r.frozen_in_data_py else r.frozen_in_data_py
        cite = "\\citep{" + ",".join(keys) + "}" if keys else "--"
        L.append(f"{tt(r.unit)} & {r.group} & {r.n_features} & {r.kind} & {r.draft_v1} & {now} & {r.rule} & {cite} \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    open(os.path.join(tdir, "tab_annotation_full.tex"), "w").write("\n".join(L))

    # ---- macros ----
    N = OrderedDict()
    N["PsNFiles"] = str(len(corpus)); N["PsNExe"] = str(int((corpus.kind == "exe").sum()))
    N["PsNDll"] = str(int((corpus.kind == "dll").sum()))
    N["PsSizeMinKB"] = f"{corpus['size'].min() / 1024:.0f}"; N["PsSizeMedianKB"] = f"{corpus['size'].median() / 1024:.0f}"
    N["PsSizeMaxMB"] = f"{corpus['size'].max() / 2 ** 20:.1f}"
    N["PsNSigned"] = str(int(corpus.has_signature.sum())); N["PsNDebug"] = str(int(corpus.has_debug.sum()))
    N["PsMachines"] = ", ".join(sorted(set(corpus.machine)))
    is32 = corpus.file.map(arch_of) == "PE32"
    N["PsNFilesPeThirtyTwo"] = str(int(is32.sum())); N["PsNFilesPeSixtyFour"] = str(int((~is32).sum()))
    for ar, k in (("PE32", "PsThirtyTwo"), ("PE32+", "PsSixtyFour")):
        da = D[(D.scope == "in") & (D.arch == ar)]
        if len(da):
            N[k + "NEdited"] = big(len(da))
            N[k + "GroupsLeCeilPct"] = pct((da.n_groups <= R_CEIL).mean(), 1)
            N[k + "EpsLeTenthPct"] = pct((da.eps_needed <= 0.1).mean(), 1)
    N["PsLiefVersion"] = str(F["lief_version"]).split("-")[0]
    Din = D[D.scope == "in"]
    N["PsNEditedInScope"] = big(len(Din))
    N["PsNEditTypesInScope"] = str(sum(1 for e in EDITS if EDIT_SCOPE[e] == "in"))
    N["PsDraftBoxInsidePct"] = pct(Din.draft_box_inside.mean(), 1)
    N["PsDraftGroupInsidePct"] = pct(Din.draft_group_inside.mean(), 1)
    N["PsDraftImmutableChangedPct"] = pct(Din.draft_immutable_changed.mean(), 1)
    N["PsDraftMonotoneDecreasedPct"] = pct(Din.draft_monotone_decreased.mean(), 1)
    N["PsDraftOutsideRangePct"] = pct(Din.draft_outside_training_range.mean(), 1)
    N["PsRepairedInsidePct"] = pct((Din.repaired_box_inside & Din.repaired_group_inside).mean(), 1)
    N["PsNMutableDraft"] = big(mut_d.sum()); N["PsNMutable"] = big(mut_r.sum())
    N["PsNMonotoneDraft"] = str(int(mono_d.sum())); N["PsNMonotone"] = str(int(mono_r.sum()))
    N["PsNAttackableDraft"] = str(len(att_d)); N["PsNAttackable"] = str(len(att_r))
    N["PsNUnits"] = str(len(EV)); N["PsNUnitsChanged"] = str(int((EV.draft_v1 != EV.frozen_in_data_py).sum()))
    N["PsRCeil"] = str(R_CEIL)
    N["PsGroupsLeCeilPct"] = pct((Din.n_groups <= R_CEIL).mean(), 1)
    N["PsGroupsLeOnePct"] = pct((Din.n_groups <= 1).mean(), 1)
    N["PsEpsLeTenthPct"] = pct((Din.eps_needed <= 0.1).mean(), 1)
    N["PsEpsLeTrainPct"] = pct((Din.eps_needed <= 0.05).mean(), 1)       # at the certified-training budget 0.05
    N["PsEpsLeOnePct"] = pct((Din.eps_needed <= 1).mean(), 1)
    N["PsEpsLeTenPct"] = pct((Din.eps_needed <= 10).mean(), 1)
    for e in REBUILD_CONTROL:
        k = "Ps" + NUM[e.split("_")[0]]
        N[k + "OwnGroupsMed"] = f"{Mall.loc[e].groups_edit_only_median:.0f}"
        N[k + "OwnGroupsMax"] = str(int(Mall.loc[e].groups_edit_only_max))
        N[k + "RebuildGroupsMed"] = f"{Mall.loc[e].groups_rebuild_median:.0f}"
    # 1h: files whose has_relocations flag flips under an overlay append (a LIEF 0.10.1 artefact: the flag is
    # False when the relocation table ends at the end of the file, True once bytes follow it)
    i_rel = unit_index()["General.has_relocations"][0]
    Xf, ff, fed = F["X"], F["fname"], F["edit"]
    o_rel = {f: Xf[i, i_rel] for i, f in enumerate(ff) if fed[i] == "orig"}
    N["PsNRelocArtefact"] = str(len({f for i, f in enumerate(ff) if fed[i] == "E1_overlay" and Xf[i, i_rel] != o_rel[f]}))
    N["PsNBodmasOverlap"] = str(n_bodmas)
    for e in EDITS:
        if e not in Mall.index:
            continue
        r, k = Mall.loc[e], "Ps" + NUM[e.split("_")[0]]
        N[k + "Files"] = str(int(r.n_files)); N[k + "GroupsMed"] = f"{r.groups_median:.0f}"
        N[k + "GroupsMax"] = str(int(r.groups_max)); N[k + "EpsMed"] = fe(r.eps_median); N[k + "EpsNinety"] = fe(r.eps_p90)
        N[k + "DraftBoxPct"] = pct(r.draft_box_inside); N[k + "DraftGroupPct"] = pct(r.draft_group_inside)
    up = man[man.edit == "E9_upx"]
    for v, k in (("default", "PsUpxDefault"), ("force", "PsUpxForce")):
        N[k + "Packed"] = str(int(((up.variant == v) & (up.status == "ok")).sum()))
    N["PsUpxGuardCf"] = str(int(up.status.str.contains("GUARD_CF").sum()))
    N["PsNImportFail"] = str(int(((man.edit == "E4_imports") & (man.variant == "1") & man.status.str.startswith("failed")).sum()))
    with open(os.path.join(tdir, "numbers_ps.tex"), "w") as f:
        f.write("% auto-generated by tools/problem_space.py -- do not edit by hand\n")
        for k, v in N.items():
            assert k.startswith("Ps") and k.isalpha(), k
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print("\ncoverage:")
    for c in cov:
        print("   %-46s %-4s %-30s EMBER groups max %d | main %s | second %s" % c)
    print(f"\nwrote 4 tables and {len(N)} macros to {tdir}")


if __name__ == "__main__":
    main()
