# Playbook: Windows persistence (scheduled tasks, registry Run keys, accounts)

**Applies to:** scheduled task creation, registry Run-key/Startup-folder writes, local
account creation, group-membership changes. MITRE **T1053.005** (Scheduled Task),
**T1547.001** (Registry Run Keys), **T1136.001** (Create Local Account), **T1098**
(Account Manipulation).

## Known false-positive pattern in THIS lab — check this FIRST
Confirmed live 2026-08-20 (see `PROJECT-STATE.md`): a routine Windows Update scheduled
task fired `Scheduled Task Created (Persistence)` purely from normal OS activity, no
attacker involved. **Before treating a scheduled task as an attack, check the task
name/path**:
- Benign OS/vendor built-ins — task paths under `\Microsoft\Windows\UpdateOrchestrator\`,
  `\Microsoft\Windows\WindowsUpdate\`, or vendor auto-update tasks (Google, Adobe,
  OneDrive) with recognizable, unmodified names → **benign**, low severity.
- Suspicious — task name/path is random-looking, lives under a user's `Temp`/`AppData`,
  runs an unusual binary (powershell.exe, cmd.exe, mshta.exe, an unsigned .exe) with
  obfuscated arguments, or was created by a non-system account shortly after other
  suspicious activity on the same host → **malicious**, treat as real persistence.

## Triage steps
1. Extract the task name/path, the account that created it, and the command it runs.
2. Match the task path against the known-benign patterns above.
3. If not obviously benign: `search_past_cases(<hostname>)` for prior activity on this
   host, and check what else happened around the same timestamp (privilege escalation,
   a new account, a suspicious PowerShell block — persistence rarely appears alone).
4. For account-creation/group-membership alerts: was the account/group change made by
   an expected admin process, or does it correlate with other suspicious activity?

## Decision guidance
- Recognized OS/vendor built-in task → **benign**, low severity, N/A technique,
  confidence ~0.9.
- Custom/unusual task or account change with no clear administrative explanation →
  **malicious**, medium/high severity, confidence ~0.8, technique as tagged.
- Genuinely unsure (task name doesn't match either pattern clearly) → escalate, do not
  guess.

## Response
- Persistence mechanisms don't have a "block an IP" containment action — there's no
  attacker network address here, only a local host action. `containment_allowed()`
  will correctly find no IP target and refuse; this is expected, not a failure.
- A confirmed malicious persistence finding should be escalated to a human for host
  remediation (remove the task/account), not auto-closed even if source attribution is
  clear — this project's guard has no automated host-remediation action, only network
  containment.
