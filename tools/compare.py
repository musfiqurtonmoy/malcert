"""Compare two results.json files: list numeric leaves differing by more than THR (fractions; 0.01 = 1 point)."""
import json, sys

THR = 0.01
a_path, b_path = sys.argv[1], sys.argv[2]
A, B = json.load(open(a_path)), json.load(open(b_path))


def flat(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from flat(v, f"{p}.{k}" if p else k)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from flat(v, f"{p}[{i}]")
    else:
        yield p, o


fa, fb = dict(flat(A)), dict(flat(B))
print("keys only in ref:", sorted(set(fa) - set(fb)))
print("keys only in new:", sorted(set(fb) - set(fa)))
print("\nconfig differences:")
for k in sorted(fa):
    if k.startswith("config") and k in fb and fa[k] != fb[k]:
        print(f"  {k}: {fa[k]} -> {fb[k]}")
print("\nviolations:")
for k in sorted(fb):
    if k.endswith("violations"):
        print(f"  {k}: ref {fa.get(k)} new {fb[k]}")
print(f"\nnumeric differences > {THR} (ref -> new, delta in points):")
n = 0
for k in fa:
    if k.startswith("config") or k not in fb:
        continue
    x, y = fa[k], fb[k]
    if isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
        if k.endswith(("violations", "n_subsets")) or ".data." in k:
            if x != y:
                print(f"  COUNT {k}: {x} -> {y}")
            continue
        if abs(x - y) > THR:
            n += 1
            print(f"  {k}: {x:.4f} -> {y:.4f}  ({100*(y-x):+.1f})")
print(f"total: {n}")
