# Run next (started by the author from a terminal)

## Stage 3g: uniform-ball ε sweep (about 20–25 min; REVISION_LOG 3-16, 3-17)

40 models: ε_train 0.05, 0.1, 0.2, 0.5, 1, 2, 4 and the largest containment radius (≈ 290), family split, seeds 0–4.
Resumable: if it stops, paste the same line again (finished models are skipped). Do not change code while it runs.

```powershell
cd "D:\Users\Public\Downloads\VS code\malcert_release"; $env:GIT_EXE = "D:\malcert_envs\git\Library\cmd\git.exe"; $py = "C:\Users\USER\miniconda3\envs\malcert\python.exe"
& $py tools/eps_sweep.py --seeds 0,1,2,3,4 --out results_eps_sweep
```

Watch: `Get-Content results_eps_sweep\log.txt -Tail 15 -Wait`. When it is done, tell Claude: it runs
`python tools/eps_sweep.py --analyse` (summary, accuracy-matched comparison, figure, `numbers_sweep.tex`).

## Stage 3: remaining run (2026-11-14)

**Done (2026-11-14):** all six runs finished; run 2 went into `results_family_s34` (REVISION_LOG 3-13).
Kept for the record:

Runs 1, 3, 4, 5, 6 below finished (exit code 0). Run 2 was refused at start by a bug in the resume check
(REVISION_LOG 3-10), so it goes into a **new folder** with the unchanged code (about 50 min):

```powershell
cd "D:\Users\Public\Downloads\VS code\malcert_release"; $env:GIT_EXE = "D:\malcert_envs\git\Library\cmd\git.exe"; $py = "C:\Users\USER\miniconda3\envs\malcert\python.exe"
& $py run_all.py --preset full --split family --seeds 3,4 --blocks clean,attacks,ablation,certified --out_dir results_family_s34
```

- Do not change `run_all.py` or `malcert/` before it finishes (the code hash must equal that of `results_family`).
- Resume does **not** work until the bug is fixed: if the run stops, delete `results_family_s34` and start the line again.
- When it is done, tell Claude: it runs
  `python tools/stats.py --family results_family results_family_s34 --random results_random` (seeds 0–4 pooled).

## Stage 3 final runs (about 6.5–7 h in total; run them one at a time, in this order)

Rules for every run:
- Start it from a PowerShell terminal; keep the PC awake (Settings > System > Power: sleep "Never" while running).
- **Resume:** if a run stops (crash, restart, power cut), paste the **same line** again. Finished seeds and blocks
  are skipped and it continues where it stopped.
- **Do not change or commit code between the runs:** a folder only accepts results from the same code.
- Watch progress with `Get-Content <folder>\log.txt -Tail 15 -Wait` (Ctrl+C stops watching, not the run).
- Times are estimates scaled from the quick pilot; the first seed of run 1 gives the real figure.

Every line starts the same way. Paste it once per terminal first:

```powershell
cd "D:\Users\Public\Downloads\VS code\malcert_release"; $env:GIT_EXE = "D:\malcert_envs\git\Library\cmd\git.exe"; $py = "C:\Users\USER\miniconda3\envs\malcert\python.exe"
```

1. **Family split, seeds 0–2, all blocks incl. smoothing on every test point** (main split; about 1 h 55 min, 38 min per seed):
   ```powershell
   & $py run_all.py --preset full --split family --seeds 0,1,2 --out_dir results_family
   ```
2. **Family split, seeds 3–4, without smoothing** (same folder; about 50 min):
   ```powershell
   & $py run_all.py --preset full --split family --seeds 3,4 --blocks clean,attacks,ablation,certified --out_dir results_family
   ```
3. **Random split, seeds 0–2, without smoothing** (comparison with earlier work; about 1 h 10 min):
   ```powershell
   & $py run_all.py --preset full --split random --seeds 0,1,2 --blocks clean,attacks,ablation,certified --out_dir results_random
   ```
4. **Temporal cut-off 2019-12, seeds 0–2** (decay curve; about 1 h):
   ```powershell
   & $py run_all.py --preset full --split cutoff --cutoff 2019-12 --seeds 0,1,2 --blocks clean,ablation,certified --out_dir results_cut_2019-12
   ```
5. **Temporal cut-off 2020-04, seeds 0–2** (retraining; about 1 h):
   ```powershell
   & $py run_all.py --preset full --split cutoff --cutoff 2020-04 --seeds 0,1,2 --blocks clean,ablation,certified --out_dir results_cut_2020-04
   ```
6. **Full-data check, 1 seed, family split, clean + main group certificate** (all 134,435 rows; about 35–45 min,
   about 3.5 GB RAM; close other programs):
   ```powershell
   & $py run_all.py --preset full --split family --seeds 0 --full_data --ablation_only_main --blocks clean,ablation --out_dir results_fulldata
   ```

When all six are done, tell Claude: it runs the analysis tools (`tools/stats.py`, `tools/temporal_decay.py`,
`tools/make_runtime.py`) and checks every `violations` count.

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
