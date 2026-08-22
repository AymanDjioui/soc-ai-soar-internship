# Playbook: Network/service reconnaissance (port scans, nmap)

**Applies to:** `ET SCAN` signatures, `pfsense_portscan`, nmap NSE User-Agent
detections. MITRE **T1046** (Network Service Discovery).

## Triage steps
1. Identify the source IP and whether it's external or our own red-team Kali
   (`100.125.163.9`, Tailscale) — authorized testing, not an incident.
2. `search_past_cases(<src ip>)` for prior scanning history from the same source.
3. If the source is unfamiliar and external, consider `run_analyzer(<ip>, "GreyNoise")`
   — GreyNoise specifically distinguishes mass-internet background scanners (very
   common, usually not worth escalating) from a scanner NOT seen broadly elsewhere
   (more likely a targeted probe against us specifically). This is exactly the
   scanner-vs-targeted-attacker question GreyNoise exists to answer.
4. Note the scope: a scan against many ports/hosts vs. a narrow, deliberate probe of
   one exposed service reads differently (broad = likely automated/mass; narrow +
   accurate = more likely a human doing recon on us specifically).

## Decision guidance
- Internal/Tailscale/red-team source → the guard will refuse containment regardless;
  assess honestly as what it is (recon, real technique) but expect L2/no-block.
- External source with GreyNoise confirming "observed scanning the internet broadly" →
  lean toward **malicious but low priority** (mass scanner, not targeted), medium
  confidence — still real recon, but not urgent.
- External source, GreyNoise shows NOT broadly observed (or unavailable) and past-case
  history shows nothing → **malicious**, medium severity, technique T1046, confidence
  ~0.8 — treat as a real, unconfirmed-scope probe worth a human's attention.

## Response
- Containment (block the scanning source) is decided by `containment_allowed()` —
  eligible if external, routable, not protected.
- Recon alone rarely warrants urgent escalation unless it precedes/accompanies a
  follow-on exploitation attempt from the same source — check for that pattern via
  `search_elasticsearch` before concluding low severity.
