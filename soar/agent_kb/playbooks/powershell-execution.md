# Playbook: Suspicious PowerShell execution

**Applies to:** PowerShell script-block logging alerts, "Suspicious PowerShell
Execution" signatures. MITRE **T1059.001** (Command and Scripting Interpreter:
PowerShell).

## Known false-positive pattern in THIS lab — check the script block content FIRST
Confirmed live 2026-08-20 (see `PROJECT-STATE.md`): an alert fired on the script block
`$global:?` — a **harmless built-in PowerShell automatic variable check**, not
attacker code. PowerShell script-block logging is noisy by design; most captured
blocks are ordinary admin/system activity, not attacks.

- **Benign** — the script block is a bare variable reference (`$global:?`, `$?`,
  `$PSVersionTable`, `$env:...`), a simple built-in cmdlet call with no obfuscation
  (`Get-Process`, `Get-Service`, `Set-ExecutionPolicy` from a known admin context), or
  matches normal scheduled/system automation already seen on this host.
- **Malicious** — the block contains encoding/obfuscation (`-enc`, `-EncodedCommand`,
  `-e `, long base64 blobs), a download/execute pattern (`IEX`, `Invoke-Expression`,
  `DownloadString`, `Net.WebClient`, `-WindowStyle Hidden`, `-NoProfile -NonInteractive`
  stacked together), credential access (`Invoke-Mimikatz`, `Get-Credential` outside an
  expected admin flow), or explicit disabling of security controls
  (`Set-MpPreference -DisableRealtimeMonitoring`).

## Triage steps
1. Read the actual script block content — this is the single most decisive signal.
   Do not judge on the alert *title* alone ("Suspicious" is the signature's own label,
   not a verified verdict).
2. Check the host and account it ran under: our own admin activity (documented lab
   tooling, e.g. `Invoke-WebRequest` from a known automation account) is expected.
3. `search_past_cases(<hostname>)` — if this exact class of script block has fired
   before and was resolved FalsePositive, weight toward benign.

## Decision guidance
- Bare variable / simple built-in cmdlet, no obfuscation → **benign**, low severity,
  N/A technique, confidence ~0.9.
- Obfuscated/encoded, download-and-execute, or credential-access pattern →
  **malicious**, high severity, technique T1059.001, confidence ~0.9.
- Script block content not visible in the alert, or genuinely ambiguous → escalate,
  do not guess from the title alone.

## Response
- No network IP target typically exists for a local script-execution alert; the guard
  correctly refuses containment (no target) — expected, not a failure.
- A confirmed malicious PowerShell execution should escalate to a human for host-level
  response (kill the process, isolate the host) — outside this project's automated
  network-containment scope.
