# Playbook: Command-and-Control (C2) beacon

**Applies to:** ET MALWARE / ET CNC beacon signatures, Cobalt Strike / AsyncRAT /
AdaptixC2 patterns, or any alert describing regular-interval callbacks to an external
host flagged as a known C2. MITRE **T1071.001** (Application Layer Protocol: Web).

## Triage steps
1. Identify the external C2 IP (the non-internal endpoint of the beacon).
2. If the alert or an observable states the IP is a **known-malicious C2** (threat-intel
   source such as ThreatFox / VirusTotal / AbuseIPDB, or an ET MALWARE C2 signature),
   that is decisive evidence — treat as **malicious**, do not wait for more.
3. Check `search_past_cases(<C2 ip>)` for prior sightings and dispositions.
4. Note the internal host(s) beaconing out — they are likely compromised and need
   follow-up regardless of the block.

## Decision guidance
- External IP + known-malicious C2 designation → **verdict malicious, severity high/critical,
  technique T1071.001, confidence ≥ 0.9.** A "no matching signature history" or an empty
  SIEM search does NOT lower this — a private lab cannot see a public C2's reputation
  locally; the threat-intel designation is the authority.
- If the external endpoint is NOT flagged malicious and there is no beacon regularity, it
  may be benign periodic traffic → escalate for human confirmation.

## Response
- Containment (block the external C2 IP on pfSense) is decided by `containment_allowed()`.
  An external, routable, non-protected C2 IP is eligible for automated containment.
- After a confirmed block, the case may be auto-closed at L1 as a handled TruePositive.
- Always flag the internal beaconing host for human follow-up (containment of the C2 does
  not remediate the compromised host).
