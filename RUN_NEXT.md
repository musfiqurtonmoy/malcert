# Run next (started by the author from a terminal)

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
