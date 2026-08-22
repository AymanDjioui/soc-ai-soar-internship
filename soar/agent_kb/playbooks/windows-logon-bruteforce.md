# Playbook: Windows logon brute-force

**Applies to:** `Windows Logon Brute-Force Detected`, repeated Security 4625 (failed
logon) events, SMB/RDP/WinRM credential guessing. MITRE **T1110** (Brute Force).

## Triage steps
1. Identify the source IP and the targeted account(s). Our red-team Kali
   (`100.125.163.9`, Tailscale) is authorized testing.
2. Distinguish the vector: SMB (445), RDP (3389), WinRM (5985/5986) — each is a different
   exposure story.
3. `search_past_cases(<src ip>)` and `search_past_cases(T1110)` for history.
4. Check for a **4624 success** following the 4625 failures (successful logon = the
   brute-force worked → severity high/critical, treat as compromise).
5. Watch for false positives from normal Windows startup activity (a service retrying
   with a stale credential) — corroborate with the count and interval.

## Decision guidance
- External source + sustained failed Windows logons → **malicious, severity medium**
  (high/critical if a 4624 success follows), technique T1110, confidence ~0.85.
- Internal/Tailscale source → escalate for confirmation; guard refuses to block it.
- Low count, matches a known service account retry → likely benign, low severity.

## Response
- Containment of an external source IP is decided by `containment_allowed()`.
- On a successful logon after the failures, escalate to a human — this is a live
  credential-access incident, not a routine brute-force, and must not be auto-closed.
