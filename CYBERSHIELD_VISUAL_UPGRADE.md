# CIBER Visual + Terminal Upgrade

- High-resolution ICO is loaded and cleaned once per process.
- Startup shield is rendered at 52x28 terminal pixels using ANSI true-colour half-blocks.
- The shield performs a smooth Y-axis turn while remaining fixed in place.
- Startup layout is deliberately minimal: title, status, shield, progress, prompt.
- No side panels are drawn during animation, avoiding cramped/clipped CMD output.
- Frame scheduling uses `time.perf_counter()` to reduce jitter and drift.
- The existing defensive command router and PowerShell read-only allowlist remain intact.
- Arbitrary CMD/PowerShell execution is not enabled.
