# CyberShield CIBER — Professional Command Pack

## GitHub publishing

Use either:

```text
ciber github-publish https://github.com/OWNER/REPO
```

or:

```text
ciber githubga joyla https://github.com/OWNER/REPO
```

`PUBLISH_TO_GITHUB.bat` is also included. It asks for the exact repository URL and then runs the verified publisher.

Authentication is intentionally not stored in the project. Use your normal GitHub CLI login (`gh auth login`) or an already-authenticated Git remote.

## Windows diagnostics

The terminal exposes fixed, read-only wrappers for useful CMD diagnostics such as:

- `systeminfo`
- `ipconfig`
- `routes`
- `arp`
- `netstat`
- `tasklist`
- `drivers`
- `netsh-interfaces`
- `netsh-wlan`
- `powercfg`
- `whoami-groups`
- `net-accounts`
- `net-share`
- `schtasks`

## PowerShell diagnostics

Additional read-only commands include:

- `get-process`
- `get-service`
- `get-netadapter`
- `get-netipconfiguration`
- `get-nettcpconnection`
- `get-netudpendpoint`
- `get-dnsclientservers`
- `get-netroute`
- `get-firewallprofile`
- `get-netfirewallrule`
- `get-mpcomputerstatus`
- `get-mppreference`
- `get-mpthreatdetection`
- `get-bitlockervolume`
- `get-localuser`
- `get-localgroup`
- `get-localgroupmember-admin`
- `get-scheduledtask`
- `get-startupapps`
- `get-hotfix`
- `get-computerinfo`
- `get-ciminstance-os`
- `get-ciminstance-computer`
- `get-eventlog-security`
- `get-eventlog-system`
- `get-eventlog-application`
- `get-bitsjob`

Arbitrary `cmd.exe`, `powershell -Command`, `-EncodedCommand`, shell pipelines, and eval-style execution remain blocked. This keeps CIBER a defensive security terminal instead of an unrestricted shell.
