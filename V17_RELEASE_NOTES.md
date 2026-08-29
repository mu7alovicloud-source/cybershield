# CyberShield V17 — CIBER Live Operator

## Fixes
- Replaced the repeated block startup animation with a fixed-frame, slowly rotating ICO animation.
- Long-running CIBER actions keep the spinner/ICO alive until the real worker finishes.
- CIBER now treats `ciber ciber` as help/status instead of an unknown request.
- Uzbek natural-language GitHub phrases (`githubga yubor`, `githubga joyla`, `githubga yukla`) route correctly.
- GitHub publishing no longer initializes/commits a local repository when GitHub CLI is unavailable.
- GitHub PASS requires a real remote push and verification.
- Added safe CyberShield panel launching from standalone CIBER (`settings`, etc.) without arbitrary shell execution.
- `main.py desktop --panel settings` opens the allowlisted Settings panel.

## Safety
CIBER remains a defensive operator. Arbitrary cmd.exe, PowerShell, shell, eval and user-provided executable launch remain blocked. Unknown samples are not executed on the host.

## Verification
- Python compileall: PASS
- Automated tests: PASS
