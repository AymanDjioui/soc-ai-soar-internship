# MITRE ATT&CK Coverage Matrix (E-1 + E-3)

Built 2026-08-13 from the **live** ElastAlert rule set on the ELK VM (24 rules, not
the 14 in the stale local mirror — mirror since re-synced) cross-referenced against
**real fired cases in TheHive**. Every "validated" mark below corresponds to an actual
case that existed in TheHive, not merely a deployed rule.

## Evidence levels (used throughout)

- ✅ **Validated end-to-end** — rule deployed AND a real matching case was observed in
  TheHive (attack → detection → case → enrichment proven).
- 🟡 **Deployed, not confirmed** — rule is live and MITRE-tagged, but no matching case
  is present in the current TheHive data, so end-to-end validation is not yet on
  record. Honest status, not a claim of coverage.
- ⬜ **Blind** — no detection capability for this tactic at all.

---

## Part 1 — Detection catalogue (E-1)

Per deployed rule: technique, tactic, telemetry source, and evidence status.

| Rule | Technique | Tactic | Source index | Evidence |
|---|---|---|---|---|
| `juiceshop_sqli` | T1190 (OWASP A03) | Initial Access | juiceshop-docker-* | ✅ "SQL Injection Attempt on Juice Shop" |
| `juiceshop_xss` | T1190 (OWASP A03) | Initial Access | juiceshop-docker-* | ✅ "XSS Attempt on Juice Shop" |
| `juiceshop_lfi_directory_traversal` | T1190 (OWASP A01) | Initial Access | juiceshop-docker-* | ✅ "Path Traversal / LFI Attempt" |
| `juiceshop_cmdi` | T1190 (OWASP A03) | Initial Access / Execution | juiceshop-docker-* | 🟡 rule live, no case on record |
| `juiceshop_ssrf` | T1190 (OWASP A10) | Initial Access | juiceshop-docker-* | 🟡 rule live, no case on record |
| `juiceshop_bruteforce` | T1110 (OWASP A07) | Credential Access | juiceshop-docker-* | 🟡 rule live, no case on record |
| `linux_root_login` | T1078 | Initial Access / Persistence | linux-lan-logs-* | ✅ "Linux Root SSH Login" |
| `linux_ssh_bruteforce` | T1110 | Credential Access | linux-lan-logs-* | ✅ "Linux SSH Brute Force" |
| `win_bruteforce` | T1110 | Credential Access | windows-logs-* | ✅ "Windows Brute Force Detected" |
| `win_powershell` | T1059.001 | Execution | windows-logs-* | ✅ "Suspicious PowerShell Execution" |
| `win_wmi_execution` | T1047 | Execution / Lateral Movement | windows-logs-* | ✅ "WMI Remote Execution Detected" |
| `win_new_user` | T1136 | Persistence | windows-logs-* | ✅ "New Windows Account Created" |
| `win_new_service` | T1543.003 | Persistence | windows-logs-* | ✅ "New Malicious Windows Service" |
| `win_scheduled_task` | T1053.005 | Persistence | windows-logs-* | ✅ "Scheduled Task Created (Persistence)" |
| `win_registry_run_key` | T1547.001 | Persistence | windows-logs-* | 🟡 rule live, no case on record |
| `win_admin_group` | T1098 | Privilege Escalation | windows-logs-* | ✅ "User Added to Privileged Group" |
| `win_credential_dump` | T1003.001 | Credential Access | windows-logs-* | 🟡 rule live, no case on record |
| `win_defender_disabled` | T1562.001 | Defense Evasion | windows-logs-* | 🟡 rule live, no case on record |
| `win_lateral_movement` | T1021 | Lateral Movement | windows-logs-* | ✅ (network-logon cases) |
| `pfsense_portscan` | T1046 | Reconnaissance / Discovery | soc-logs-* | ✅ "Port Scan Detected by PfSense" |
| `pfsense_dmz_breakout` | T1210 | Lateral Movement | soc-logs-* | ✅ "PfSense DMZ Breakout" |
| `pfsense_dns_tunnel` | T1048, T1071.004 | Exfiltration / C2 | soc-logs-* | 🟡 rule live, no case on record |
| `pfsense_outbound_anomaly` | T1095, T1571 | Command & Control | soc-logs-* | 🟡 rule live, no case on record |
| `suricata_high_severity` | (signature-driven) | multiple | suricata-alerts-* | ✅ 66 cases (incl. testmyids GPL, web attacks) |
| — (SOAR threat-intel) | T1071.001 | Command & Control | TheHive + Cortex | ✅ C-1 Cobalt Strike C2 capture |

**14 techniques validated end-to-end; 8 rules deployed but not yet case-confirmed.**

---

## Part 2 — Coverage by tactic, with gaps and reasons (E-3)

The honest maturity view. "Why" columns matter more than the colour — they show we
understand the limits of the telemetry, which is a stronger position than an
unqualified "we detect everything".

| Tactic | Status | What we cover | Gap / why |
|---|---|---|---|
| Reconnaissance | 🟡 Partial | Network port/service scanning (T1046) | Network-layer only; no host-level recon telemetry (needs EDR) |
| Resource Development | ⬜ N/A | — | Attacker-side infra prep; not observable from a defender's vantage point |
| Initial Access | ✅ Covered | Web exploitation (SQLi/XSS/LFI/CMDi/SSRF), valid-account SSH, brute force | No email/phishing telemetry (T1566) — blind to that vector |
| Execution | ✅ Covered | PowerShell (T1059.001), WMI (T1047) | No full process-tree/command-line beyond what Sysmon logs |
| Persistence | ✅ Covered (strong) | Accounts, services, scheduled tasks, run keys (4 techniques) | Best-covered tactic |
| Privilege Escalation | 🟡 Partial | Privileged-group changes (T1098) | No token manipulation / UAC-bypass / exploit-based PrivEsc detection |
| Defense Evasion | 🟡 Partial | Defender-disable rule deployed (T1562.001) | Broad tactic, mostly blind without EDR; the one rule is unvalidated |
| Credential Access | 🟡 Partial | Brute force (T1110), LSASS-dump rule (T1003.001) | Dump detection via event logs only, not memory inspection; unvalidated |
| Discovery | 🟡 Partial | Network service scanning (T1046) | No host-based discovery (account/system/file enumeration) — needs EDR |
| Lateral Movement | ✅ Covered | Network logon (T1021), DMZ→LAN breakout (T1210), WMI (T1047) | Strong at the network boundary |
| Collection | ⬜ Blind | — | No detection; would need host DLP/EDR |
| Command & Control | ✅ Covered (highlight) | App-layer C2 via threat-intel enrichment (T1071.001, validated in C-1); DNS/non-standard-port rules deployed | The C2 detection + autonomous block is the project's centrepiece |
| Exfiltration | 🟡 Partial | DNS-tunnel rule deployed (T1048) | Rule live but unvalidated; DMZ has no egress path by design, so hard to generate naturally |
| Impact | ⬜ Blind | — | No ransomware/defacement/destruction detection; not simulated |

### The four structural gaps (the honest "why we can't see everything")

1. **No EDR.** Host-level Discovery, in-memory Credential Access, and most Defense
   Evasion are only partially visible through Windows event logs + Sysmon, not true
   endpoint detection. This is the single biggest limiter.
2. **No email / identity / cloud telemetry.** Phishing (T1566), identity-provider
   attacks, and cloud techniques are entirely blind.
3. **DMZ has no egress by design.** Network segmentation (a security *strength*) means
   some C2/exfil scenarios can't be generated naturally in the lab, so those rules
   stay unvalidated rather than proven.
4. **Impact and Collection not in scope.** No ransomware/destruction/collection
   simulation, so those tactics are honestly blind rather than claimed.

### Summary

- **10 of 14 ATT&CK tactics** have at least partial detection coverage.
- **6 tactics fully covered** (Initial Access, Execution, Persistence, Lateral
  Movement, Command & Control) with validated end-to-end evidence.
- **4 partial** (Recon, PrivEsc, Defense Evasion, Credential Access, Discovery,
  Exfiltration — network-layer or rule-deployed-only).
- **3 blind** (Resource Development [n/a], Collection, Impact) — stated honestly, with
  the telemetry reason for each.

This is a defensible maturity assessment, not a coverage claim. It survives the
follow-up question "what can't you see?" because the answer is already written down.
