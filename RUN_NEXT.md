# Run next (started by the author from a terminal)

## 2i validation tuning grid: grouped 3-fold CV on the family split (about 70–80 min on the GTX 1050 Ti)

Train + validation of the seed-0 family split, 3 family-disjoint folds; the test part is never used.
Expected time, scaled from the 3-fold smoke test: per-view LightGBM main 25 min and second 6 min, edit-aware
CROWN-IBP 18 min, MLP 8 min, uniform and box CROWN-IBP 8 min, aligned7 MLP views 6 min, data loading 1 min.
Keep the PC awake; the GPU and about 3 GB of RAM are in use.

```powershell
cd "D:\Users\Public\Downloads\VS code\malcert_release"
$env:PYTHONPATH = "."
& "C:\Users\USER\miniconda3\envs\malcert\python.exe" tools\tune_validation.py --split family --out results_tuning
```

Output: `results_tuning\<model>.csv` (one row per grid point) and `results_tuning\chosen.json`.
Then tell Claude; it freezes the chosen settings in `config.py` and commits before Stage 3.

## Backup to a private GitHub repository (REVISION_PLAN 1i.6) — needs your GitHub login

1. In a browser, sign in at https://github.com, then open https://github.com/new
   - Repository name: `malcert` (any name works)
   - Visibility: **Private**
   - Do **not** add a README, .gitignore or licence (the repository must be empty)
   - Click **Create repository** and copy the HTTPS address it shows, e.g. `https://github.com/<you>/malcert.git`
2. In PowerShell (replace the address with yours):

   ```powershell
   cd "D:\Users\Public\Downloads\VS code\malcert_release"
   $git = "D:\malcert_envs\git\Library\cmd\git.exe"
   & $git remote add origin https://github.com/<you>/malcert.git
   & $git push -u origin revision-1 main --tags
   ```

3. The first push opens a **Git Credential Manager** window: choose *Sign in with your browser*, approve
   the request in the browser. Windows then stores the login, so later pushes need no password.
4. Check: the repository page on GitHub shows branches `main` and `revision-1` and tag `draft-v1`,
   and no `data/` or `ps_corpus/` folder.

What is pushed: code, tests, tools, `paper/`, `ps_results/`, results folders, logs (about 13 MB).
What is not pushed (`.gitignore`): `data/` (BODMAS), `ps_corpus/` (copies of Windows binaries), `ps_tools/` (UPX).
The commits are authored as "Md. Musfiqur Rahman <musfiqurtonmoy@gmail.com>"; GitHub shows that name and address.

After every later commit: `& $git push`
