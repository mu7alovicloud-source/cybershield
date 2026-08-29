# CyberShield CIBER V16

`ciber` is an AI operator sub-mode inside the terminal. It does **not** launch the CyberShield desktop UI.

## Real-time terminal UX
- Uses the shipped `cibershield.ico` as the animation source.
- Startup slowly rotates the icon in memory and redraws the screen without cursor-save debris.
- Long-running CIBER actions run on a worker thread while the main terminal paints a live rotating icon and elapsed time.
- Existing operator timeouts remain the hard safety bounds.

## Verified safe actions
- GitHub publish/status/push/pull/clone via allowlisted Git/GitHub CLI calls.
- Vercel deploy with deployment URL verification.
- EXE build with PyInstaller and output-file verification.
- Project tests through a fixed `python -m pytest -q` argv.
- Project map, bounded project search, bounded source-file read and dependency checks.
- CyberShield security scans, diagnostics, forensic audits and telemetry.

## Safety boundary
CIBER never turns natural language into arbitrary `cmd.exe`, PowerShell, shell, `eval`, or user-supplied executable invocation. A tool is considered successful only when its concrete verification passes.

## Commands
```text
ciber
ciber help
ciber loyiha xaritasini ko‘rsat
ciber CyberShield so‘zini loyihadan qidir
ciber main.py faylini o‘qi
ciber testlarni ishga tushir
ciber githubga private qilib yubor OWNER/REPO
ciber vercelga production deploy qil
ciber exe yarat
```
