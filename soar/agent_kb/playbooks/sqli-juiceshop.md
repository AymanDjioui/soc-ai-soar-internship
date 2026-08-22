# Playbook: SQL Injection against the Juice Shop DMZ app

**Applies to:** alerts tagged `juiceshop_sqli`, or Suricata Web Application Attack
signatures targeting `172.16.0.10` / the `8080` NAT path. MITRE **T1190**.

## Triage steps
1. Identify the source IP and confirm it is **external** (not `100.64.0.0/10` Tailscale,
   not RFC1918). Our own red-team traffic arrives from Kali `100.125.163.9` (Tailscale) —
   that is authorized testing, not an incident.
2. Inspect the request body/URI for the injection class:
   - keyword-based (`UNION`, `SELECT`, `sleep`, `benchmark`) → classic extraction attempt
   - boolean/comment-based (`' OR 1=1--`, `' AND`, `';`) → auth-bypass / blind SQLi
     (this class was a detection blind spot until the `juiceshop_sqli` filter was widened).
3. Check reputation of the source IP (VirusTotal, AbuseIPDB, OTX).
4. Check whether the same IP appears in prior cases and how they were dispositioned.

## Decision guidance
- External source + malicious payload + corroborating threat-intel → **malicious**, high
  confidence. Eligible for automated containment IF the source is external and routable.
- Source in Tailscale/RFC1918 range → this is our own lab/admin traffic → **do not block**
  (the guard will refuse regardless); escalate for human confirmation.
- Payload present but source reputation clean → still likely a real attempt against a
  public app; treat as malicious-but-unconfirmed and escalate rather than auto-act.

## Response
- Containment (block source IP on pfSense) is decided by `containment_allowed()`, never by
  the analyst/agent directly. The agent's job ends at a well-evidenced verdict.
- Notify via the Mailer responder on a malicious verdict.
