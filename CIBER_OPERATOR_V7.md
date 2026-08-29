# CyberShield CIBER Operator V7

`ciber` is the safe Claude-like terminal entry point. It supports explicit actions, not arbitrary shell execution.

## Real operator behavior

The operator accepts limited natural-language requests and maps them only to
CyberShield allowlisted actions. It never sends free-form user text to CMD,
PowerShell, Bash, `eval`, or `shell=True`. External tools are executed with
argv, bounded timeouts, captured output, and verification.

A publishing/deployment action has up to five ordered strategies. The first
verified success returns `passed_strategy=N`; if all fail, the result is a real
FAIL/manual-handoff and never a fake PASS.

## Commands
- `ciber status`
- `ciber github-publish OWNER/REPO` — tries up to 5 strategies and reports the exact passed strategy.
- `ciber vercel-deploy` or `ciber vercel-deploy production` — tries up to 5 strategies and never fakes PASS.
- `ciber build-exe` — invokes PyInstaller if installed; no separate build script is required.

The operator uses `shell=False` and an allowlist (`git`, `gh`, `vercel`, `pyinstaller`). It does not expose arbitrary CMD/PowerShell.


## Terminal startup

```text
python main.py terminal
python launch_cybershield.py terminal
```

Inside the terminal, `help` shows the operator entry point and `commands` shows
the complete registered allowlist. `ciber help` shows the natural-language
operator catalog.
