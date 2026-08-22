# Playbook: Credential dumping

**Applies to:** `reg save HKLM\SAM`/`HKLM\SYSTEM`, LSASS memory access, Impacket
`secretsdump`-style activity. MITRE **T1003.002** (OS Credential Dumping: SAM).

## Triage steps
1. Identify the host and the account that ran the dumping command. A domain
   admin/system account performing this outside a known backup/maintenance window is
   a strong signal; an interactive user account doing it is almost never legitimate.
2. Check the exact command: `reg save HKLM\SAM <path>` / `HKLM\SYSTEM <path>` is the
   textbook local-SAM-dump pattern — there is no benign reason for an ordinary process
   to do this.
3. `search_past_cases(<hostname>)` for prior activity, and check what happened
   immediately before (initial access/exploitation) and after (exfiltration, lateral
   movement) on the same host — credential dumping is a pivot point in an attack
   chain, rarely an isolated event.

## Decision guidance
- `reg save` against SAM/SYSTEM, or equivalent LSASS/secretsdump activity, with no
  administrative/backup justification → **malicious**, severity **high**, technique
  T1003.002, confidence ~0.9. This is one of the least ambiguous techniques — do not
  hedge to inconclusive on a clear match.
- Only escalate to lower confidence if there's a documented, known-legitimate backup
  process on this host that does exactly this (rare; verify via past-case history
  before assuming it).

## Response
- No network IP containment target typically exists for a local credential-dump
  action — the guard correctly finds nothing to block; this is expected.
- Always escalate a confirmed credential dump to a human — extracted credentials
  enable follow-on compromise (lateral movement, privilege escalation) that this
  project's automated containment cannot remediate (it only blocks network IPs, not
  compromised credentials).
