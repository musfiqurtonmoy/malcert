# Run next (started by the author from a terminal)

## 2i validation tuning grid (about 35–45 min on the GTX 1050 Ti; validation split only)

The plan asks for the family split, which is built in Stage 3b. Choose one:
- **(a) now, on the random split**, seed 0:

  ```powershell
  cd "D:\Users\Public\Downloads\VS code\malcert_release"
  $env:PYTHONPATH = "."
  & "C:\Users\USER\miniconda3\envs\malcert\python.exe" tools\tune_validation.py --split random --out results_tuning
  ```
- **(b) after Stage 3b**, on the family split: the same command with `--split family --out results_tuning_family`
  (the script refuses `family` until 3b exists).

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
