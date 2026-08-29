# CyberShield Safe Lab + GitHub Terminal

## GitHub terminal

The terminal supports bounded GitHub CLI operations through `gh` only:

- `github auth`
- `github status`
- `github open`
- `github publish [name] --private|--public`
- `github commit <message>`
- `github push`
- `github pull`
- `github clone OWNER/REPO [directory]`

Arbitrary shell, `gh api`, repository deletion, force-push, and visibility changes are not exposed by the CyberShield command layer.

## Safe Lab

`Sandbox` is the security workspace. A sample can be statically analyzed first and, when Windows Sandbox is available, launched in a disposable Windows Sandbox with:

- networking disabled;
- Protected Client enabled;
- clipboard and printer redirection disabled;
- host sample directory mapped read-only;
- host application never directly executes the sample.

Windows Sandbox is disposable: closing it discards the guest state. It is still an isolation boundary, not a mathematical guarantee; keep samples untrusted and use a dedicated test machine for high-risk research.
