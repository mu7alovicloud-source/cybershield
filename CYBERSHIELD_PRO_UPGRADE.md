# CyberShield CIBER PRO upgrade

- Minimal half-screen startup HUD; no side panels.
- Shield animation remains fixed in place and uses cached frames.
- ICO is loaded once per cached frame instead of every paint cycle.
- Windows VT/ANSI path retained with safe fallback.
- Added defensive read-only Windows commands and PowerShell telemetry aliases.
- Arbitrary shell execution remains blocked; subprocess calls stay allowlisted and shell=False.

Verification: 27 passed.
