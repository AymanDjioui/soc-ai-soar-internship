# Graph Report - .  (2026-08-11)

## Corpus Check
- 255 files · ~158,958 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 454 nodes · 555 edges · 39 communities (33 shown, 6 thin omitted)
- Extraction: 78% EXTRACTED · 21% INFERRED · 1% AMBIGUOUS · INFERRED: 115 edges (avg confidence: 0.87)
- Token cost: 675,695 input · 0 output

## Community Hubs (Navigation)
- ElastAlert Rules and Watchdogs
- LLM Benchmark Findings
- Model Selection and Prompt Engineering
- SOAR Orchestrator (hardened)
- SOC Architecture Diagram
- LLM Adaptation Research
- Silent Pipeline Outages
- Guardrail Design and Evidence
- ELK Stack and Log Delivery
- Port Scan Detection Dashboard
- Original Orchestrator (Badr)
- XSS Detection Dashboard
- SQLi Detection Dashboard
- Detection Bridge Defects
- Juice Shop Demo Runbook
- SQLi Auth Bypass Detection
- Known-Bad Traffic Detection
- Brute Force Login Detection
- Failed Login Rate Analysis
- Project Phases and Brief
- Nmap Port Scan Attack
- IDOR Attack Chain
- Benchmark Harness
- Rescoring Tool
- sqlmap Injection Attack
- testmyids IDS Validation
- SQLi Auth Bypass Attack
- IDOR Detection View
- Brute Force Attack Tooling
- XSS Probe Attack
- pfSense Port Scan Rule
- pfSense Auto-Block Responder
- Juice Shop Log Pipeline
- Benchmarking Literature
- Suricata Forwarder Script
- Scope Discipline Rules
- DMZ Network Segmentation
- Evidence Capture Standards
- Team Ownership Split

## God Nodes (most connected - your core abstractions)
1. `process_single_alert()` - 12 edges
2. `e2e_soc_orchestrator.py — SOAR + AI triage orchestrator` - 11 edges
3. `Router/Firewall VM 100.70.145.65` - 11 edges
4. `ElastAlert2 config + TheHive connection` - 10 edges
5. `Session 2026-07-24 — Linux LAN, Windows LAN, Suricata on em1` - 10 edges
6. `SOAR platform - AWS EC2 100.124.232.121` - 10 edges
7. `IDS Detections Dashboard` - 10 edges
8. `SIEM - local VMware VM 100.99.54.59` - 9 edges
9. `IDS Detections Dashboard (Kibana)` - 9 edges
10. `mistral:7b (selected triage model)` - 8 edges

## Surprising Connections (you probably didn't know these)
- `Literature-based SOAR/AI benchmark (§6)` --semantically_similar_to--> `Local LLM Benchmark (report PDF)`  [INFERRED] [semantically similar]
  notes/badr_phase1_report (1).md → report/Local_LLM_Benchmark.pdf
- `Shuffle workflow architecture (planned)` --semantically_similar_to--> `e2e_soc_orchestrator.py — SOAR + AI triage orchestrator`  [INFERRED] [semantically similar]
  notes/archive-roadmap-2026-07-20.md → soar/README.md
- `Tailnet-only endpoint exposure pattern (Ollama/Redis)` --semantically_similar_to--> `Suricata EVE via native Redis output`  [INFERRED] [semantically similar]
  ai/results/deployment-latency.md → CLAUDE.md
- `Guardrail model (no RFC1918/CGNAT/gateway, threshold, rate limit, audit, kill switch)` --cites--> `Policy-Guided Threat Hunting with Splunk SOC triage (arxiv 2603.23966)`  [AMBIGUOUS]
  ROADMAP.md → AI-LAYER-PLAN.md
- `Defense framing sentence (every clause evidenced)` --semantically_similar_to--> `Honest defense framing (bounded autonomy claim)`  [INFERRED] [semantically similar]
  FINAL-ROADMAP.md → AI-LAYER-PLAN.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Autonomous detection-to-containment loop** — configs_elk_elastalert_rules_juiceshop_sqli_rule, configs_elk_elastalert_config_hive_connection, claude_md_thehive_cortex_soar, runbook_2026_08_11_e2e_soc_orchestrator, ai_results_model_benchmark_policy_guard, claude_md_pfsense_blocker_responder, runbook_2026_08_11_soar_audit_jsonl [EXTRACTED 1.00]
- **"Model informs, code decides" evidence chain** — roadmap_ssdp_false_positive_incident, ai_results_prompt_iteration_log_v2_safety_regression, ai_results_model_benchmark_context_overapplication, ai_results_soar_dryrun_evidence_readme_fabricated_reasoning_defect, ai_results_model_benchmark_policy_guard, report_plan_ch9_toward_autonomous_l1 [INFERRED 0.90]
- **Three-host hardware comparison (laptop VM / EC2 CPU / GCP L4 GPU)** — ai_results_deployment_latency_local_vs_ec2, ai_results_deployment_latency_decision_reversal, ai_results_deployment_latency_gpu_l4_host, ai_results_deployment_latency_host_specific_accuracy, ai_results_model_benchmark_mistral7b [EXTRACTED 1.00]
- **Dead-man-switch watchdog family across all five ingest pipelines** — configs_elk_elastalert_rules_watchdog_pfsense_filterlog_rule, configs_elk_elastalert_rules_watchdog_suricata_eve_rule, configs_elk_elastalert_rules_watchdog_windows_logs_rule, configs_elk_elastalert_rules_watchdog_linux_lan_logs_rule, configs_elk_elastalert_rules_watchdog_juiceshop_docker_rule, configs_elk_elastalert_rules_watchdog_pfsense_filterlog_limitexecution [EXTRACTED 1.00]
- **Windows intrusion kill chain covered by the win_* detections** — configs_elk_elastalert_rules_win_bruteforce_rule, configs_elk_elastalert_rules_win_powershell_rule, configs_elk_elastalert_rules_win_new_user_rule, configs_elk_elastalert_rules_win_admin_group_rule, configs_elk_elastalert_rules_win_new_service_rule, configs_elk_elastalert_rules_win_lateral_movement_rule [INFERRED 0.85]
- **Recurring silent-failure pattern: pipeline looks healthy but detection is dead** — configs_elk_elastalert_rules_suricata_high_severity_realertbug, notes_12_em1rulesetgap, notes_12_hiveapikeyoverride, notes_11_redisdownplatformwide, configs_elk_elastalert_rules_watchdog_pfsense_filterlog_syslogdoutage [INFERRED 0.85]
- **Layered containment safety stack** — soar_readme_policy_guard, soar_readme_kill_switch, soar_readme_audit_log, soar_readme_call_llm, notes_16_select_containment_target, notes_17_wait_for_responder_action [EXTRACTED 1.00]
- **Detection pipeline: pfSense/Suricata → ELK → ElastAlert → TheHive → Cortex** — notes_3_tier1_filterlog_elk, notes_3_tier2_suricata_elk, notes_7_suricata_redis_migration, notes_6_elastalert_thehive_bridge, notes_badr_phase1_report_1_thehive_cortex, notes_17_pfsense_blocker_responder [EXTRACTED 1.00]
- **Recurring silent pipeline outages motivating watchdogs** — notes_14_redis_outage, notes_9_redis_pipeline_gap, notes_15_syslogd_forwarding_bug, notes_15_watchdogs, notes_5_cron_watchdog_forwarder [INFERRED 0.85]

## Communities (39 total, 6 thin omitted)

### Community 0 - "ElastAlert Rules and Watchdogs"
Cohesion: 0.06
Nodes (46): Index suricata-alerts-*, query_key src_ip.keyword (per-source realert), Global-realert silencing defect (18 alerts, 0 delivered), ElastAlert rule: Suricata High Severity Alert, Advisory-only silence ambiguity (app idle vs down), Watchdog: juiceshop-docker-* silent 4h, Watchdog: linux-lan-logs-* silent 4h, limit_execution croniter constraint (* 8-19 * * *) (+38 more)

### Community 1 - "LLM Benchmark Findings"
Cohesion: 0.06
Nodes (39): Honest defense framing (bounded autonomy claim), GPU host benchmark (NVIDIA L4, 71x warm speedup), Start-per-session cost discipline, Finding 15 — over-applying prompt context (false negative on external scan), Experiment 3 — GPU re-match against larger recommended models, llama3.2:3b mode collapse (capability floor), policy_guard() — deterministic, veto-only containment gate, Finding 1/11 — parameter count does not predict performance (+31 more)

### Community 2 - "Model Selection and Prompt Engineering"
Cohesion: 0.06
Nodes (36): ROADMAP Task B1 — AI Layer Foundation, ai/benchmark.py — model/prompt/schema harness, deployment-latency.md — local vs cloud latency study, Enum-constrained MITRE JSON schema (constrained decoding), Golden Test Set (7 real lab alerts), mistral:7b (benchmark winner), Prompt v2 auto-block regression, ai/rescore.py — rescoring from immutable raw outputs (+28 more)

### Community 3 - "SOAR Orchestrator (hardened)"
Cohesion: 0.10
Nodes (31): assess_enrichment(), audit(), build_ai_comment(), call_llm(), containment_allowed(), is_operational_alert(), kill_switch_active(), main() (+23 more)

### Community 4 - "SOC Architecture Diagram"
Cohesion: 0.11
Nodes (31): AbuseIPDB analyzer, AI integration for detection improvement (upcoming), Analyzers group, Auto-Block flow (Webhook + SSH easyrule), Cortex analyzer/responder engine, SOC SOAR+AI Architecture Diagram, DMZ 172.16.0.0/24, Elastalert2 alert forwarding (+23 more)

### Community 5 - "LLM Adaptation Research"
Cohesion: 0.08
Nodes (24): CORTEX: collaborative LLM agents for alert triage (arxiv 2510.00311), Few-shot prompting, Fine-tuning deliberately rejected, LLM deployment decision (own AWS EC2, not laptop/Badr's box), Four-layer LLM adaptation stack (prompting → few-shot → RAG → fine-tuning), Retrieval-Augmented Generation (stretch goal), Retrieval-Augmented LLMs for Security Incident Analysis (arxiv 2603.18196), Schema-constrained structured outputs (Ollama format parameter) (+16 more)

### Community 6 - "Silent Pipeline Outages"
Cohesion: 0.12
Nodes (19): Week-long silent Redis-on-pfSense outage (3rd occurrence), Logstash grok filterlog_data capture bug, limit_execution interval-cron trap in ElastAlert, pfSense syslogd not forwarding to ELK, A-1 Pipeline watchdogs (ElastAlert flatline dead-man switches), pfSense remote syslog to 100.99.54.59:5514, Tailscale overlay pivot (bridged → NAT → overlay), Hardware offloading disabled — Suricata prerequisite (+11 more)

### Community 7 - "Guardrail Design and Evidence"
Cohesion: 0.12
Nodes (18): 7-case golden test set from real lab alerts, Policy-Guided Threat Hunting with Splunk SOC triage (arxiv 2603.23966), safe_to_auto_block is an opinion, not permission, Finding 8 — the model never selects OTHER / never admits ignorance, Measured precision/recall tradeoff (fixing FPs created FNs), Fabricated enrichment reasoning defect (confidence raised on clean engines), "Model informs, code decides" demonstrated on live data, PfSense_Blocker Cortex responder (+10 more)

### Community 8 - "ELK Stack and Log Delivery"
Cohesion: 0.14
Nodes (14): Tailnet-only endpoint exposure pattern (Ollama/Redis), ELK 8.15.0 stack @ 100.99.54.59, Suricata EVE via native Redis output, ELK docker-compose stack (ES, Kibana, Logstash, ElastAlert2), A-1 — watchdog flatline rules (done 2026-08-06), "Capture isn't detection" — em1 silent-failure finding, Ch.10 — engineering incidents and lessons, Dual-layer detection split (network IDS vs application logging) (+6 more)

### Community 9 - "Port Scan Detection Dashboard"
Cohesion: 0.21
Nodes (14): Alerts Over Time Histogram (30s buckets, 142 total, 8 unique signatures), Top Attacker IPs (100.85.83.119, 172.16.0.10), Attacker Geolocation Map (MaxMind GeoLite2 City), IDS Detections Dashboard, Kibana IDS Detections Dashboard - Port Scan Evidence, Kibana (Elastic) Dashboard, EVE JSON via TCP to Logstash 100.99.54.59:5516, ET SCAN Nmap Scripting Engine User-Agent Detected (+6 more)

### Community 10 - "Original Orchestrator (Badr)"
Cohesion: 0.24
Nodes (12): call_llm(), main(), mock_llm_final_decision(), mock_llm_triage(), print_analyzer_report(), process_single_alert(), Step 8 & 9: Second LLM call. The LLM acts as Tier 2 Analyst/Responder. It looks…, Polls a Cortex analyzer job until it reaches a terminal state (Success or… (+4 more)

### Community 11 - "XSS Detection Dashboard"
Cohesion: 0.22
Nodes (13): Alerts Over Time histogram (30s buckets), Attacker Geolocation map (no country results), ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt, IDS Detections Dashboard (Kibana), Kibana (Elastic), Total Alerts = 2, Unique Signatures = 1, Kibana IDS Detections Dashboard - XSS Detection Screenshot, Top attacker IP 100.85.83.119 (Tailscale) (+5 more)

### Community 12 - "SQLi Detection Dashboard"
Cohesion: 0.19
Nodes (13): 14 Alerts / 8 Unique Signatures (Last 15 minutes, 2026-07-16), Attacker IP 100.85.83.119 (Tailscale), IDS Detections Dashboard (Kibana), Kibana IDS Detections Dashboard - SQLi Screenshot, Kibana (Elastic 8.15), ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access, ET SCAN Sqlmap SQL Injection Scan, ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT in HTTP URI (+5 more)

### Community 13 - "Detection Bridge Defects"
Cohesion: 0.18
Nodes (11): select_containment_target() src/dst role fix, win_bruteforce.yaml missing/invalid query_key defect, C-1 blocked: threat feeds do not flag lab traffic, Suricata→TheHive bridge dropping 100% (realert without query_key), ELK → TheHive bridge via Elastalert2, suricata_high_severity.yaml ElastAlert rule, JVM heap misconfiguration and OOM kills, Badr Phase 1 Report (v1) (+3 more)

### Community 14 - "Juice Shop Demo Runbook"
Cohesion: 0.22
Nodes (10): Kibana dashboard: Juice Shop Traffic & Security Overview, Tailscale->NAT->DMZ demo path 100.70.145.65:8080, Live Demo Runbook — Attack Scenarios, Scenario 3: SQL injection / sqlmap, Scenario 2: XSS probe (SID 2009714), Dual-layer detection: network IDS vs application logging, Session 2026-07-20 — Juice Shop dashboard & live attack demo, Stale Kibana data view hardcoded to one index (+2 more)

### Community 15 - "SQLi Auth Bypass Detection"
Cohesion: 0.25
Nodes (9): Juice Shop access_log Data Source (access_log.* fields), Attacker Source 100.85.83.119 (djioui, curl/8.5.0), Juice Shop /rest/user/login Endpoint, Kibana / Elastic Stack (Discover), MITRE ATT&CK T1078 Valid Accounts (auth bypass), MITRE ATT&CK T1190 Exploit Public-Facing Application, Saved Search 'Juiceshop - Suspicious Request Events' (6 documents), SQL Injection Authentication Bypass (' OR 1=1--) (+1 more)

### Community 16 - "Known-Bad Traffic Detection"
Cohesion: 0.36
Nodes (8): Top Attacker IP 217.160.0.187 (Germany), Alert Category: Potentially Bad Traffic (100%), Kibana (Elastic) Dashboards, Kibana IDS Detections Dashboard - Known Bad Traffic, Signature: GPL ATTACK_RESPONSE id check returned root, Suricata IDS (alert source), Targeted Hostname testmyids.com, Dashboard panels: geo map, total alerts, unique signatures, alerts over time, severity/category pies, top signatures, top IPs, alerts by country

### Community 17 - "Brute Force Login Detection"
Cohesion: 0.43
Nodes (8): Attacker client IP 100.85.83.119 (285 requests, Tailscale), Brute-Force Login Detection on /rest/user/login, Kibana Dashboard: Juice Shop Traffic & Security Overview (brute-force login detection), OWASP Juice Shop (DMZ victim app), Juice Shop access_log data source (request_uri, client_ip, status), Detection Rule: Failed Login Attempts Over Time (401 spike from single client IP), MITRE ATT&CK T1110 Brute Force, Kibana (Elastic 8.15) Dashboards

### Community 18 - "Failed Login Rate Analysis"
Cohesion: 0.39
Nodes (8): Attack window ~20:04-20:06, July 20 2026, Baseline low-volume failures (~5 per bucket), Brute-force login attack scenario (Juice Shop), Failed-login burst: 35 failures in one 30s bucket, Kibana dashboard panel (Juiceshop app logs), Rate-over-time threshold detection logic, @timestamp per 30 seconds count aggregation, Juice Shop Failed Login Attempts Over Time (Kibana histogram)

### Community 19 - "Project Phases and Brief"
Cohesion: 0.29
Nodes (7): Decision: self-hosted Shuffle + Ollama for AI triage, Phase 1 — Lab setup (pfSense, ELK, TheHive/Cortex), Phase 2 — Benchmark of AI + SOAR solutions for ELK, Phase 3 — Benchmark of agents, automation, orchestration, Project brief: SOAR + AI on the SIEM (Devoteam), Report structure draft outline, TheHive+Cortex as baseline SOAR (one-shot responders)

### Community 20 - "Nmap Port Scan Attack"
Cohesion: 0.38
Nodes (7): Port Scan Evidence Screenshot (Nmap vs pfSense 8080), OWASP Juice Shop fingerprinted behind NAT port-forward, Nmap 7.94SVN service/version scan (nmap -sV -sC -p 8080), MITRE ATT&CK T1046 Network Service Discovery / active recon, Suricata/pfSense IDS detection of the scan (detected-by-firewall-ids evidence set), Attack path over Tailscale to pfSense NAT :8080, Target pfsense.tail880415.ts.net (100.70.145.65) port 8080/tcp open http-proxy

### Community 21 - "IDOR Attack Chain"
Cohesion: 0.48
Nodes (7): Basket ID enumeration loop (1-5, Bearer token), SQL Injection Auth Bypass (' OR 1=1--), Juice Shop /rest/basket/$id endpoint, Juice Shop via Tailscale NAT 100.70.145.65:8080, IDOR (Insecure Direct Object Reference), IDOR Attack Terminal Capture (Juice Shop), curl (REST API client)

### Community 22 - "Benchmark Harness"
Cohesion: 0.53
Nodes (5): build_messages(), call_ollama(), main(), policy_guard(), Deterministic containment policy. Returns True only if the source IP may be…

### Community 23 - "Rescoring Tool"
Cohesion: 0.47
Nodes (5): main(), parse_name(), policy_guard(), Deterministic containment policy — code, not model opinion. Veto-only., Handles both naming generations: new: <schema>__<prompt>__<model>__<case>.json…

### Community 24 - "sqlmap Injection Attack"
Cohesion: 0.40
Nodes (6): SQLi sqlmap Terminal Capture, AND Boolean-Based Blind Injection (param q), SQL Injection Attack Technique, SQLite Back-end DBMS, sqlmap 1.8.4 (SQL Injection Tool), Juice Shop Target (100.70.145.65:8080 rest/products/search)

### Community 25 - "testmyids IDS Validation"
Cohesion: 0.47
Nodes (6): curl (traffic generation tool), Known-Bad Traffic Detection Validation (ET POLICY / GPL ATTACK ID check), pfSense 2.8.1-RELEASE root shell (pfSense.home.arpa), Terminal: curl testmyids.com from pfSense shell, Suricata WAN (em0) egress inspection, testmyids.com IDS Test Request (uid=0(root) gid=0(root) response)

### Community 26 - "SQLi Auth Bypass Attack"
Cohesion: 0.53
Nodes (6): SQLi Auth Bypass Terminal Capture, Admin JWT token returned (admin@juice-sh.op, HTTP 200), curl POST to /rest/user/login, Payload ' OR 1=1-- in login email, SQL Injection Authentication Bypass, Juice Shop Target via Tailscale NAT 100.70.145.65:8080

### Community 27 - "IDOR Detection View"
Cohesion: 0.47
Nodes (6): IDOR Detection - Kibana Juiceshop Top Request URIs, IDOR Attack (sequential /rest/basket/1-5 enumeration), Juice Shop Application Access Log (access_log.*), Kibana Data Table Visualization, MITRE ATT&CK T1190 Exploit Public-Facing Application, Detection Rule: Top Request URIs aggregation on access_log.request_uri.keyword

### Community 28 - "Brute Force Attack Tooling"
Cohesion: 0.60
Nodes (5): Brute-force Login Attack Terminal (Juice Shop), Password List (password/123456/admin/qwerty/letmein) for admin@juice-sh.op, Juice Shop REST Login Endpoint (100.70.145.65:8080/rest/user/login), Brute-force Password Guessing (T1110), curl Bash Loop Attack Tool

### Community 29 - "XSS Probe Attack"
Cohesion: 0.83
Nodes (4): Terminal: XSS Probe via curl against Juice Shop, curl XSS Payload (script alert demo2), Target: Juice Shop via Tailscale NAT 100.70.145.65:8080, Reflected XSS Attack Technique

### Community 30 - "pfSense Port Scan Rule"
Cohesion: 0.67
Nodes (3): hivealerter output (portscan), ElastAlert rule: pfsense_portscan (T1046), Index soc-logs-* (pfSense filterlog)

### Community 31 - "pfSense Auto-Block Responder"
Cohesion: 0.67
Nodes (3): PfSense_Blocker Cortex responder, resolve_responder_id() — name to select, hash to call, Custom Cortex bash auto-block responder

### Community 32 - "Juice Shop Log Pipeline"
Cohesion: 0.67
Nodes (3): Juice Shop HTTP log pipeline (nginx-proxy), Alpine system clock 3 days behind, §7.8 Juice Shop DMZ → pfSense syslog-ng relay → SIEM

## Ambiguous Edges - Review These
- `Policy-Guided Threat Hunting with Splunk SOC triage (arxiv 2603.23966)` → `Guardrail model (no RFC1918/CGNAT/gateway, threshold, rate limit, audit, kill switch)`  [AMBIGUOUS]
  AI-LAYER-PLAN.md · relation: cites
- `query_key src_ip.keyword (per-source realert)` → `ET DOS SSDP Amplification false-positive noise from 192.168.10.30`  [AMBIGUOUS]
  notes/12.md · relation: conceptually_related_to
- `C-1 blocked: threat feeds do not flag lab traffic` → `TheHive ↔ Cortex integration`  [AMBIGUOUS]
  notes/17.md · relation: references
- `SOAR platform - AWS EC2 100.124.232.121` → `AI integration for detection improvement (upcoming)`  [AMBIGUOUS]
  Architecture.jpeg · relation: conceptually_related_to
- `Port Scan Evidence Screenshot (Nmap vs pfSense 8080)` → `Suricata/pfSense IDS detection of the scan (detected-by-firewall-ids evidence set)`  [AMBIGUOUS]
  screenshots/detected-by-firewall-ids/01-port-scan/01-port-scan.png · relation: conceptually_related_to
- `Attacker Geolocation map (no country results)` → `Top attacker IP 100.85.83.119 (Tailscale)`  [AMBIGUOUS]
  screenshots/detected-by-firewall-ids/02-xss/02-dashboard.png · relation: conceptually_related_to
- `Brute-force login attack scenario (Juice Shop)` → `Attack window ~20:04-20:06, July 20 2026`  [AMBIGUOUS]
  screenshots/detected-by-juiceshop-app/01-bruteforce-login/detection-2.png · relation: conceptually_related_to
- `SQL Injection Authentication Bypass (' OR 1=1--)` → `MITRE ATT&CK T1078 Valid Accounts (auth bypass)`  [AMBIGUOUS]
  screenshots/detected-by-juiceshop-app/02-sqli-auth-bypass/detection.png · relation: conceptually_related_to

## Knowledge Gaps
- **90 isolated node(s):** `suricata_forward.sh script`, `SOC Lab Architecture (WAN/LAN/DMZ + Tailscale)`, `PfSense_Blocker Cortex responder`, `Triage JSON schema (summary/severity/mitre/confidence)`, `CORTEX: collaborative LLM agents for alert triage (arxiv 2510.00311)` (+85 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Policy-Guided Threat Hunting with Splunk SOC triage (arxiv 2603.23966)` and `Guardrail model (no RFC1918/CGNAT/gateway, threshold, rate limit, audit, kill switch)`?**
  _Edge tagged AMBIGUOUS (relation: cites) - confidence is low._
- **What is the exact relationship between `query_key src_ip.keyword (per-source realert)` and `ET DOS SSDP Amplification false-positive noise from 192.168.10.30`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `C-1 blocked: threat feeds do not flag lab traffic` and `TheHive ↔ Cortex integration`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `SOAR platform - AWS EC2 100.124.232.121` and `AI integration for detection improvement (upcoming)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Port Scan Evidence Screenshot (Nmap vs pfSense 8080)` and `Suricata/pfSense IDS detection of the scan (detected-by-firewall-ids evidence set)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Attacker Geolocation map (no country results)` and `Top attacker IP 100.85.83.119 (Tailscale)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Brute-force login attack scenario (Juice Shop)` and `Attack window ~20:04-20:06, July 20 2026`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._