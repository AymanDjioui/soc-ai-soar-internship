# Playbook: SSH brute-force

**Applies to:** `linux_ssh_bruteforce`, repeated SSH auth failures, or many connections
to port 22 from one source. MITRE **T1110** (Brute Force).

## Triage steps
1. Identify the source IP and whether it is external or internal (our red-team Kali is
   `100.125.163.9` on Tailscale — authorized testing, not an incident).
2. Check the log pattern: `Failed password` (real guesses reaching auth) vs
   `Timeout before authentication` (connection dropped early — often host-level
   fail2ban/IPS silently starving the SIEM of the pattern it expects; a real finding,
   note it).
3. `search_past_cases(<src ip>)` for prior brute-force history from the same source.
4. Check whether any attempt SUCCEEDED (a `Accepted password`/`session opened` after the
   failures) — that escalates severity sharply.

## Decision guidance
- External source + sustained failed SSH auth → **malicious, severity medium** (high if a
  success followed), technique T1110, confidence ~0.85.
- Internal/Tailscale source → likely our own tooling/testing → escalate for confirmation;
  the guard will refuse to block it regardless.
- Only `Timeout before authentication`, no `Failed password` → host-level defense is
  active; low severity, note the SIEM-visibility gap, escalate if unsure.

## Response
- Containment of an external source IP is decided by `containment_allowed()`.
- If a login succeeded, this is no longer just brute-force — escalate to a human for
  compromise investigation, do not auto-close.
