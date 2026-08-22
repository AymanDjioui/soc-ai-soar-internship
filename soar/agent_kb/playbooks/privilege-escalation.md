# Playbook: Privilege escalation

**Applies to:** UAC bypass patterns, unexpected `sudo`/setuid abuse, a process
suddenly running as SYSTEM/root without a normal elevation path. MITRE **T1548**
(Abuse Elevation Control Mechanism).

## Triage steps
1. Identify the process/binary that gained elevated privileges and the mechanism
   (UAC bypass technique, sudo misuse, SUID binary abuse, token manipulation).
2. Check whether this is a KNOWN administrative elevation (a legitimate installer,
   a documented admin script) vs. an unexpected process (a script interpreter,
   an unusual binary, something that appeared shortly after initial access/exploitation
   on the same host).
3. `search_past_cases(<hostname>)` — privilege escalation is almost always a stage in
   a larger chain; check for a preceding exploitation/initial-access alert and a
   following lateral-movement/credential-access alert on the same host and timeframe.

## Decision guidance
- Elevation via a recognized installer/admin tool with no other suspicious activity on
  the host → likely **benign**, low severity, confidence ~0.8 (still worth noting, not
  urgent).
- Elevation via a script interpreter, unusual binary, or immediately following another
  suspicious alert on the same host → **malicious**, severity **high**, technique
  T1548, confidence ~0.85 — treat as a real escalation, not noise.
- Ambiguous, no other host context available → escalate rather than guess; privilege
  escalation is high-stakes to get wrong in either direction.

## Response
- No network IP containment target typically exists for a local escalation event —
  the guard correctly finds nothing to block; this is expected.
- Escalate any confirmed privilege escalation to a human for host-level response
  (this project's automated action is network containment only, not host remediation).
