# CyberShield CIBER — Upgrade Notes

## Terminal / animation
- High-resolution ICO is loaded once instead of from disk on every animation frame.
- Animation frames are cached by angle, eliminating the main source of CMD stutter.
- Shield uses a fixed transparent canvas and smooth Y-axis turn.
- Startup dashboard is intentionally minimal: shield, status, progress, prompt.
- No side panels or repeated decorative blocks are rendered during startup.
- Long CIBER operations continue to run in a worker thread while the terminal animation remains responsive.

## Defensive command pack
Added real, bounded read-only Windows/PowerShell diagnostics including:
- defender-status / defender-threats
- firewall-rules
- listening-ports
- dns-cache
- network-profile
- volumes / physical-disks
- net-users / net-localgroup / net-session / net-file
- server/workstation statistics
- legacy WMI inventory helpers

`commands-by-category <category>` can filter the professional catalog.

## Safety
The terminal remains an allowlisted defensive operator:
- no arbitrary cmd.exe execution
- no arbitrary PowerShell `-Command` / `-File`
- subprocess calls use argv arrays and `shell=False`
- destructive operations remain explicitly gated
- scan/sandbox behavior remains non-destructive by default

## Verification
The upgraded project test suite passed:

30 passed
