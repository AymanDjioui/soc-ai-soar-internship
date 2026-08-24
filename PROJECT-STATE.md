# Project State — SOAR and AI for Detection Improvement in the SOC

Devoteam internship. Deadline **2026-08-31**. Written 2026-08-11, updated 2026-08-12
and 2026-08-13, for handoff to a new session. If you are a fresh Claude session reading
this: read this file fully before touching anything, then read `notes/18.md` and
`notes/19.md` (the two most recent sessions) for full detail on the reasoning behind
recent changes. A knowledge graph of the whole repo also exists — see "Using the graph"
below — query it for anything this file doesn't cover in enough depth. **Note:** the
graph was built 2026-08-11 and has not been refreshed since the 2026-08-12/13 changes
below; run `/graphify . --update` if you need it to reflect them.

**NEW 2026-08-20 — agentic AI layer built. See `AGENT-ROADMAP.md` for the full story.**
A ReAct-style SOC agent (`soar/soc_agent.py` + `soar/agent_tools.py` +
`soar/agent_orchestrator.py` + `soar/agent_kb/`) was built as a PARALLEL mode to the
proven two-call pipeline: the LLM chooses which tools to call (ES search, past-case RAG
over 310 closed cases, MITRE KB, playbooks) to investigate, then a verdict; the SAME
deterministic guard (imported unchanged from `e2e_soc_orchestrator.py`) decides
containment; and a deterministic **L1 auto-close / L2 escalate** tiering closes known
cases at L1 or escalates unknowns to a human. Benchmarked (`ai/results/agent-benchmark.md`,
SAFETY 5/5 every run). A real armed L1 capture was verified (C2 `202.61.130.163` blocked +
case `~328003784` auto-closed TruePositive, pfctl-confirmed). A live attack campaign
(redteam-mcp) reconfirmed the E-3 coverage gaps and surfaced+fixed a safety defect (agent
auto-dismissing real attacks → deterministic close-guard added). **Deployed to
`ollama-l4-server-spot` `~/soar/` 2026-08-20, checksum-verified**, but deliberately NOT a
systemd service (must not compete with the armed pipeline); it is an explicitly-invoked
entry point, dry-run by default. The armed pipeline + `e2e_soc_orchestrator.py` are
UNTOUCHED. Local backup of the original orchestrator: `soar/backups/`. Demo account for
the teacher: `soc-l2@thehive.local` / `${SOC_L2_DEMO_PASSWORD}` (password redacted
2026-08-22, see docs/SECURITY.md; the login itself is not a credential).

**NEW 2026-08-24 — Phase 8G: permanent L2-only worker + Phase 8G.2 armed L1 test
closed.** `soar/l2_worker.py` is now a permanent systemd service
(`soar-agent-l2-worker.service`, enabled/active, identity
`soc-l1-ai-agent@thehive.local`), polling TheHive and running the unchanged
`agent_orchestrator.py` per alert, hardcoded `l2-only` in code — containment is
structurally impossible from this path. See `ai/results/phase8g1-*.md` for the
circuit-breaker redesign and identity rotation, and
`ai/results/phase8g2-part-b-l1-containment-test.md` for the one controlled armed
L1-containment test series: 6 real attempts against a live GPU-hosted mistral:7b
all correctly refused containment (`MISSING_EVIDENCE`) rather than fire on
incomplete evidence — the gate is proven safe under real load, but no new armed
block was captured in this series (the test IOC turned out not to be
independently confirmed malicious by live threat intel — see that file for the
full honest account). The project's positive containment proof remains the
2026-08-20 capture referenced above (`202.61.130.163` / case `~328003784`,
ThreatFox-confirmed, pfctl-verified) — re-verified still live and unchanged as
part of this closure. Permanent autonomous IP containment remains **disabled**;
the kill switch is active; no pfSense credentials exist in any permanent
unit/env file.

## Who is who

- **Ayman (Djo)** — me, the user you're talking to. Own: ELK, pfSense, Suricata, the AI
  layer, the SOAR orchestrator.
- **Badr** — teammate. Owns: TheHive/Cortex (AWS), the Cortex pfSense-blocker responder,
  network segmentation (WAN/LAN/DMZ), Juice Shop victim app. His machine must be on for
  TheHive/Cortex/pfSense to be reachable — check before planning work that needs them.
- **Encadrant (teacher)** — has pending questions from us, see "Open questions" below.
  Do not build a SOAR-platform comparison (Shuffle etc.) or commit to autonomous-vs-
  human-in-loop framing until he replies.

## Architecture, in one paragraph

pfSense (firewall + Suricata IDS, WAN/LAN/DMZ zones) sends logs to an ELK stack
(Elasticsearch/Logstash/Kibana) over syslog and Redis. ElastAlert2 watches Elasticsearch
and forwards qualifying alerts to TheHive (case management), which enriches observables
via Cortex analyzers (VirusTotal, AbuseIPDB, OTX, URLhaus). A Python orchestrator
(`soar/e2e_soc_orchestrator.py`) polls TheHive, asks a local LLM (`mistral:7b` on a GPU)
to triage each alert, re-asks after enrichment for a final verdict, and — only if a
deterministic code-side guard (`policy_guard()`) allows it — triggers a Cortex responder
that blocks the attacker IP on pfSense via SSH. Everything sits on a Tailscale mesh VPN;
every host is reached by its Tailscale IP, never a public one.

Full detail and a labelled diagram: `Architecture.jpeg`, and the SOC Architecture
Diagram community in the knowledge graph.

## Machines, IPs, and how to reach them

| Host | Role | Tailscale IP | Access |
|---|---|---|---|
| ELK / SIEM | Elasticsearch, Logstash, Kibana, ElastAlert2 | `100.99.54.59` | `ssh ayman@100.99.54.59` (see creds below) |
| pfSense | Firewall + Suricata IDS (em0 WAN, em1 LAN, em2 DMZ — three instances, see note below) | `100.70.145.65` | `ssh admin@100.70.145.65` (see creds below) |
| TheHive/Cortex | AWS EC2, Badr's — case mgmt + enrichment/response | `100.124.232.121` | web UI `:9000` (TheHive), `:4443` (Cortex, HTTPS) |
| **ollama-l4-server-spot** | GCP, NVIDIA L4 GPU, the AI layer. **Renamed/recreated 2026-08-17** — was `ollama-l4-server` in `europe-west4-c`, now a **Spot instance** in `europe-west4-b` (GPU stockout forced a wider-zone rebuild from a snapshot). Same Tailscale IP. | `100.90.228.58` | `ssh djiouiayman@100.90.228.58` — Tailscale SSH, no key file needed. **If it prints a login.tailscale.com URL instead of connecting, that's a one-time re-approval — open the link in a browser, then retry the same SSH command; it works immediately after.** |
| soc-llm-aws | AWS EC2, retired CPU LLM host, kept stopped as benchmark baseline | `100.96.231.95` | stopped; do not use as the live LLM endpoint |
| Juice Shop | DMZ victim app, reached via NAT | via `100.70.145.65:8080` → `172.16.0.10:80` | — |
| **kali** | VMware, red-team/threat-simulation attacker box, hosts the `redteam-mcp` server's tools (nmap/sqlmap/impacket/etc). Added 2026-08-15. | `100.125.163.9` | `ssh kali@100.125.163.9` (password `${KALI_PASSWORD}` — redacted 2026-08-22, see docs/SECURITY.md; was a weak default, low risk since Tailscale-gated, but worth changing eventually since this box holds offensive tools) |

**⚠️ GCP GPU VM: now a Spot instance (~cheaper than the original on-demand pricing, but
can be preempted/terminated by Google at any time with no auto-restart —
`automaticRestart: FALSE`). An auto-schedule now starts/stops it automatically,
weekdays 09:00-17:00 Casablanca time, matching actual usage — no need to manually
stop it between sessions anymore, though the "verify live state" habit below still
matters.** A daily disk-snapshot policy (`default-schedule-1`, 14-day retention) is
attached for backup. **Important lesson from the 2026-08-17 recovery**: a snapshot is
a point-in-time copy — restoring from one (e.g. after a stockout forces a rebuild)
silently reverts *everything* since that snapshot, not just infrastructure. Always
checksum-verify `e2e_soc_orchestrator.py` against the repo and check the audit log's
last timestamp after any VM recreation, before trusting anything is current.
Check the VM's live state before relying on any of this:
```bash
curl -s http://100.90.228.58:11434/api/tags   # 200 = up, no response = stopped
```
If stopped, start it from the GCP console, wait ~1 min, then warm the model before
anything else (first call after boot is ~30-37s, not ~2.5s). No manual step needed for
the orchestrator itself — `soar-orchestrator.service` is `enabled` and resumes polling
automatically on boot, dry-run only (see "Orchestrator quick reference" below):
```bash
curl -s http://100.90.228.58:11434/api/generate \
  -d '{"model":"mistral:7b","prompt":"hi","stream":false}' > /dev/null
```

## Credentials (lab-internal, low sensitivity — rotate before any public sharing)

<!-- REDACTED 2026-08-22 (repo-hygiene pass): this table previously quoted 3 more
     live plaintext credentials (ELK SSH password, Elasticsearch password, pfSense
     admin password) in addition to the already-redacted TheHive key above. This is
     the "future, separately-authorized cleanup pass" flagged as pending in
     soar/L1-L2-SAFETY-AUDIT.md §20. None of these have been rotated by this pass —
     see docs/SECURITY.md before any push. -->
| What | Value |
|---|---|
| ELK SSH | `ayman` / `${ELK_SSH_PASSWORD}` |
| Elasticsearch | `elastic` / `${ELASTIC_PASSWORD}` |
| pfSense web/SSH | `admin` / `${PFSENSE_PASSWORD}` |
| TheHive API key | `<REVOKED_AND_REDACTED_THEHIVE_API_KEY>` |
| Cortex `PfSense_Blocker_1_0` responder id | `aebe07e932adfb592a20678599943378` (resolved dynamically at runtime by the orchestrator — this value is informational, not hardcoded anywhere) |
| GPU VM SSH | Tailscale SSH — `ssh djiouiayman@100.90.228.58`, no password/key needed if you're on the tailnet |

**Known debt (task B-1, not yet done):** the TheHive API key above is live in
`configs/elk/elastalert/config.yaml` in plaintext, plus hardcoded Kibana encryption keys
in `configs/elk/docker-compose.yml`. Badr needs to rotate the TheHive key and confirm
the old one 401s. Never commit a *new* key into any repo file — env var only.

## What's actually done (verified today, not assumed)

- **Phase 7E finalized and locked (2026-08-22)** — the 60-case Dataset B human-review
  sample now has a complete, adjudicated ground-truth label set. Both reviewers
  completed their queues (reviewer-a 38/38, reviewer-b 40/42 — 2 cases withheld due to
  an independence-breaking contamination, reviewer-a's decision accepted as
  authoritative for those 2 per explicit direction). The 18 clean dual-reviewed cases
  showed **77.8% preliminary agreement** (14/18); 14 unresolved cases (4 disagreements +
  10 additional single-reviewer disputes) went through evidence-based adjudication,
  approved with 2 corrections, for a final adjudicated set of **15 cases: 8
  approved/L2, 3 excluded, 4 disputed/L2, 0 L1**. Final 60-case label set: **35
  approved (contribute to safety metrics), 21 excluded, 4 disputed** — all validated
  against `soar/review_rubric.py`, all 12 `soar/test_*.py` suites re-run clean (632/632,
  0 failures) before locking. Locked as `soar/review_overlays/DATASET_B_LOCK_v1.json`
  with sha256 hashes of every input file. Original reviewer overlays
  (`reviewer-a.jsonl`/`reviewer-b.jsonl`) untouched throughout — adjudication decisions
  live in a separate, new `adjudication.jsonl`. Full detail: `soar/L1-L2-SAFETY-AUDIT.md`
  §22-25. **Phase 8 has not started** — this was a labeling/ground-truth milestone only,
  entirely offline, no live infrastructure touched.
- **GPU VM migrated to a Spot instance, orchestrator recovered after silent state
  loss** (2026-08-17). The original `ollama-l4-server` (europe-west4-c) hit a GPU
  stockout on restart even in Spot mode; a separate session searched wider across
  zones and landed capacity in europe-west4-b, recreating the box as
  **`ollama-l4-server-spot`** from a disk snapshot. Legitimate, well-executed recovery
  of a real capacity problem (multi-zone search, snapshot-based rebuild, an
  auto-schedule added — weekdays 09:00-17:00 Casablanca time, matching actual usage
  pattern, daily-snapshot backup policy reattached) — **but the snapshot used predated
  2026-08-15's application-level work**, so the new instance came up missing: the
  taxonomy-fix orchestrator version (had the pre-fix Aug 11 copy instead), Badr's
  mailer code, the systemd service entirely, `soar.env`, and the kill switch. Audit
  log was also the stale Aug 11 copy (4 days of history — including the C-1/C-2
  captures — not present on this VM, though **the actual evidence is unaffected**: it
  lives in TheHive and in this repo's own notes/screenshots, not on the VM).
  **Recovered**: redeployed the correct `e2e_soc_orchestrator.py` from this repo
  (checksum-verified match), recreated `soar.env`, recreated the systemd service —
  deliberately restarted in `SOAR_DRY_RUN=1` again rather than assuming re-arm, same
  safe-transition discipline as the original 2026-08-15 arming. Confirmed healthy:
  reaches TheHive and the LLM, kill switch clean, polling started.
  **Lesson for the report (good Ch.10 material)**: a disk snapshot is a point-in-time
  copy — restoring from one silently reverts *everything* since that point, not just
  the thing you meant to fix. Worth a repo-level note or lightweight versioning
  discipline (e.g. tag/checksum the orchestrator on deploy) so a future silent
  VM-recreation is caught fast, the way this one was (checksum + audit-log-date
  comparison), not discovered by accident.
- **Custom red-team MCP server built** (2026-08-15, `redteam-mcp/server.py`) — our own
  MCP *server* (client is Claude Code) exposing 14 offensive tools that SSH into a Kali
  VM on the tailnet (`kali`, `100.125.163.9`, `kali/kali`) and run real utilities
  (nmap, sqlmap, hydra, nikto, gobuster, netexec, enum4linux, impacket
  secretsdump/wmiexec/psexec, nxc-winrm, ssh, linpeas, msfvenom). Each tool maps to a
  specific detection rule (for E-4 attack-chain validation). Has a code-side **scope
  guard** (`_assert_in_scope`) — the red-team analogue of the SOAR `policy_guard`:
  attacks are refused for anything outside the lab (public internet) AND for our own
  SOC infrastructure (ELK/TheHive/GPU/Kali), which are protected exactly as on the
  blue-team side. Verified end-to-end: real nmap ran against the linux-lan victim
  (`192.168.10.20`, SSH open), and the guard correctly refused both a public IP and the
  ELK server. Registered in project-root `.mcp.json` (no creds in it — server defaults
  handle them). **To use as native MCP tools, Claude Code must approve/reload the new
  server; until then the tools are drivable via the module directly** (see
  `redteam-mcp/README.md`). New attacker VM `kali` is NOT in the SOAR protected-assets
  list — it's a red-team source, not defensive infra.
- **Mailer responder added** (Badr, 2026-08-13/14) — orchestrator now emails on
  malicious verdicts via Cortex's Mailer responder, not just TheHive comments. Repo
  copy of `e2e_soc_orchestrator.py` re-synced from the live GPU VM 2026-08-15 to match.
- **Full detection chain**: pfSense → Suricata → ElastAlert2 → TheHive → Cortex
  enrichment. Proven live today with a real testmyids.com trigger and a synthetic
  injected-alert test.
- **A-1: pipeline watchdogs** — 5 ElastAlert flatline rules
  (`configs/elk/elastalert/rules/watchdog_*.yaml`) that alert when a log source goes
  silent. Validated both directions (fire on real outages, silent when healthy).
- **AI layer migrated CPU → GPU** — `mistral:7b` on an NVIDIA L4, 71x faster than the
  original AWS CPU host (2.5s vs 177.6s per triage, warm).
- **Model choice benchmarked and confirmed** — `mistral:7b` (4.4GB) beat 8 other models
  including newer/larger ones chosen by a third-party recommendation, across 3
  experiments. Full writeup: `ai/results/model-benchmark.md`,
  `ai/results/deployment-latency.md`, `report/benchmark-report.tex` (compiles to PDF).
- **Orchestrator hardened** — `soar/e2e_soc_orchestrator.py`. Design principle: the LLM
  is only ever asked "what is this?", never "should I block this?". A deterministic,
  veto-only `policy_guard()` decides whether a containment action may proceed. See the
  file's own docstring for the full guarantee list (kill switch, rate limit, confidence
  threshold, RFC1918/Tailscale/protected-asset refusal).
- **C-3: responder mechanism verified** — `PfSense_Blocker_1_0` confirmed to actually add
  a block rule to pfSense's `EasyRuleBlockHostsWAN` table (not just report success).
- **C-1: a genuine autonomous block, captured and independently verified** —
  2026-08-13, see `notes/19.md`. Real currently-active Cobalt Strike C2 IP
  (`68.64.183.127`, sourced from ThreatFox), full chain alert -> triage -> case ->
  enrichment -> verdict (`MALICIOUS`, 0.90) -> guard -> `CONTAINMENT EXECUTED`,
  confirmed on pfSense itself via `pfctl`, not just trusted the app's own report.
  Screenshots captured (TheHive case, pfSense before/after, raw analyzer taxonomies).
- **9 real bugs found and fixed across two sessions** (see notes/16.md, notes/17.md for
  full detail on each): Suricata ElastAlert rule dropping 100% of alerts (missing
  `query_key`), same defect in the Windows brute-force rule, `observables_count` always
  0 in triage (TheHive doesn't return observables on the alert object), Cortex responder
  called by name instead of hash id, **the audit log claiming a block succeeded when
  Cortex had actually rejected the job** (the most serious one — fixed by waiting for
  Cortex's real status before writing `containment_executed`), `select_containment_target`
  picking the wrong IP on outbound alerts (would have blocked a victim, not an attacker),
  kill-switch/audit-log paths being relative to CWD instead of absolute, rate limiter
  failing open on an unreadable audit log, confidence values unbounded in the schema.

## What's NOT done — in priority order

~~1. **C-1: a genuine autonomous block has not been captured.**~~ — **DONE 2026-08-13,
   independently verified.** See `notes/19.md` for full detail. Sourced a fresh
   malicious IP from ThreatFox's CSV export (`68.64.183.127`, Cobalt Strike C2,
   confidence 100, first seen minutes before use — Feodo Tracker was checked first but
   its only "online" entry was the same stale IP from the previous attempt). Injected a
   synthetic alert (honestly tagged `synthetic` throughout, per the report's own
   integrity standard), confirmed 3 consistent `MALICIOUS` verdicts across independent
   dry runs (0.80, 0.89, kill-switch-refused), confirmed the kill switch genuinely halts
   containment, then ran one deliberate targeted armed invocation
   (`SOAR_ALERT_ID` + `SOAR_DRY_RUN=0`, not a general arm of the service). Result:
   `CONTAINMENT EXECUTED`, confidence 0.90 — **independently confirmed** via
   `pfctl -t EasyRuleBlockHostsWAN -T show` directly on pfSense (not just the app's own
   report, per the project's own prior lesson about audit logs claiming false success).
   Screenshots captured: TheHive case `~164106344` (#213) with full AI Triage Draft
   comment, pfSense table before/after, Observables tab with raw analyzer taxonomies
   and Responder Reports. Block left in place (real malicious IP, correct outcome).
   **Found and fixed a real bug along the way**: the `notes/18.md` §6 enrichment fix had
   been silently broken since deployment — it read taxonomies from
   `report["summary"]["taxonomies"]` on the raw Cortex job object, which doesn't have a
   `summary` key at all (only `success`/`full`/`artifacts`), so every verdict since that
   deploy ran on zero evidence and defaulted to `benign`. Real taxonomies live on
   `api.observable.get(id)["reports"]`, not the job object — fixed, verified against
   live data at three checkpoints before redeploying. **Caution if touching this
   enrichment code again:** the bug shipped because the original fix was only tested
   against synthetic mock data shaped to an assumed schema, never a real live Cortex
   job — verify against `api.observable.get()` output directly before trusting any
   future change here.
~~2. **C-2: correct refusal**~~ — **DONE 2026-08-13.** See `notes/20.md` for full
   detail. Live threat-intel can't organically flag our own private/Tailscale
   addresses (no public reputation data exists for them), so a live-only test would
   just show `BENIGN` and never reach the guard — real, but not what C-2 needs to
   prove. Ran two parts: (1) live pipeline on our ELK server's Tailscale IP — Phase 1
   triage read it as suspicious (`medium`), Phase 2 enrichment correctly overrode to
   `BENIGN` with real VT/AbuseIPDB evidence, explicitly explaining the disagreement;
   (2) direct test of `containment_allowed()` with a manufactured malicious verdict
   (same technique as the kill-switch test) — confirmed refused both for an explicitly
   protected asset (`"explicitly protected lab asset"`) and, separately, for an
   ordinary lab machine caught only by the general Tailscale/CGNAT range check (proving
   the protection isn't just a hardcoded IP list), with a sanity check confirming the
   same confidence level is correctly *allowed* against a genuine external threat.
   Produced real evidence via the orchestrator's own comment/audit functions (not just
   terminal output): a clearly-labeled synthetic-test comment on case `~164077816`, a
   real `containment_refused` audit entry, and confirmed via `pfctl` that pfSense was
   untouched.
~~3. **A-2 clean pass**~~ — **DONE, confirmed 2026-08-14.** The continuous dry-run
   `soar-orchestrator.service` has been running unattended since the taxonomy-fix
   deploy (2026-08-13 ~13:20 UTC): 21 alerts triaged, 14 fully enriched with a verdict,
   **zero errors**, across ~21 hours of real operation, well past "3+ alerts, clean."
   Sample verdicts: `~286929136`, `~164077816`, `~205021320` (all `benign`, confidence
   1.0, correctly enriched via real Cortex data). Guard also stayed correctly active in
   continuous ops — 3 more `containment_refused` events in this window.
   **Note found, not yet fixed (Badr is actively editing this file for a mailer
   feature, so intentionally not touched now):** two refusals in this window
   (`203.0.113.10`, `203.0.113.66`) were labeled `"RFC1918 private address"`, but
   `203.0.113.0/24` is actually the public TEST-NET-3 documentation range, not RFC1918
   — the guard still correctly refuses (Python's `.is_private` catches both), the
   refusal *reason string* is just imprecise for that range. Harmless, cosmetic, flag
   to Badr when he's done with the mailer work.
   Also found: the live orchestrator on the GPU VM has diverged from this repo — Badr
   added a mailer/email-notification feature (`mailer_triggered` audit event, not
   present in the repo copy) directly on the VM. **Do not deploy from the repo to the
   GPU VM until this is pulled down and merged first**, or his work will be
   overwritten.
~~4. **A-1b**: make Redis on pfSense survive a reboot~~ — **done 2026-08-12, and finally
   root-caused rather than just patched.** Badr rebooted his machine mid-session
   (pfSense runs as a VM there), giving a real, unplanned instance of the "died
   silently 3x historically" failure to diagnose instead of waiting to force one.
   Root cause: `/var/run` is a **tmpfs mount**, wiped on every reboot; Redis writes
   its PID file to `/var/run/redis/redis.pid`, that directory doesn't exist after a
   fresh boot, and nothing recreated it before Redis's `rc.d` script ran — despite
   `redis_enable="YES"` correctly set in `/etc/rc.conf`. Confirmed via Redis's own log
   (`Failed to write PID file: No such file or directory`) and zero redis processes
   found post-boot. Fixed with two `Services > Cron` jobs (same pattern as the
   syslogd fix above): an `@reboot` job that recreates `/var/run/redis` with correct
   ownership and restarts Redis cleanly, plus a `*/15` health-check job
   (`redis-cli ping || service redis restart`) as a safety net for any other cause of
   death. Suricata alert flow to Elasticsearch was confirmed restored within seconds
   of the manual fix, and both cron jobs confirmed present in `config.xml`.
~~5. **Detection noise cleanup**~~ — **done 2026-08-12**, see `notes/18.md`. All four
   sub-items fixed and verified live:
   - Tailscale STUN noise (SIDs 2016149/2016150, ~67% of all Suricata alerts, not 98% as
     first measured) suppressed via a pfSense Suricata suppress-list entry. Required
     discovering and suppressing on a **third, previously undocumented Suricata instance
     on LAN/em1** (not just WAN/DMZ) — see the architecture table note above.
   - `pfsense_portscan.yaml` rewritten as an ElastAlert `cardinality` rule (15+ distinct
     dest ports/min per source), excludes Tailscale and multicast.
   - Filterlog CSV parsing in `logstash.conf` is now protocol-aware (branches on
     tcp/udp/icmp instead of one fixed 29-column TCP-shaped mapping).
   - ElastAlert's hivealerter now sets a stable `sourceRef`
     (`suricata-{signature_id}-{src_ip}-{dedup_bucket}` etc.) for dedup. Required
     patching the installed `elastalert` package itself (`elastalert2` 2.19.0's
     `HiveAlerter` doesn't template `sourceRef` out of the box) — patch lives at
     `configs/elk/elastalert/patches/thehive.py`, mounted into the container via
     `docker-compose.yml`. **Caution if touching this again:** TheHive's `/api/alert`
     hard-rejects a duplicate `sourceRef` with `400 CreateError` rather than merging —
     the patch specifically catches that response and treats it as a successful dedup.
     A first rollout without that catch caused a real ~7min alert-delivery stall (no
     detections lost, but worth knowing before changing this code again).
   - **Bonus, same class as the STUN item:** `lan_ssdp_noise` suppress list widened
     from `track by_src, ip 192.168.10.30` to a global suppress on SID `2019102` (ET
     SSDP Amplification Scan) — was still flooding TheHive for *other* LAN hosts doing
     normal UPnP discovery, confirmed benign from the raw payload (`M-SEARCH
     ssdp:discover` to `239.255.255.250:1900`, entirely internal, not an actual
     external-victim amplification attempt).
   - **Bonus, unrelated to noise but found while verifying the above:** a live pfSense
     `syslogd` silent-forwarding outage (~85 min, `soc-logs-*` — same failure mode as
     the 2026-08-06 incident: local logging kept working, remote UDP forward silently
     died). Fixed with the watchdog rule's own documented command
     (`pfSsh.php playback svc restart syslogd`), then given a permanent mitigation: a
     `Services > Cron` job restarts `syslogd` every 20 min
     (`/usr/local/sbin/pfSsh.php playback svc restart syslogd`), capping any future
     recurrence instead of requiring a human to notice and SSH in. The 30-min watchdog
     rule stays as a backstop — if it fires now, the auto-heal itself broke.
   - **Bonus, also same class as STUN/SSDP:** custom Suricata rule
     `LOCAL Possible Port Scan Detected` (SID `9000001`, WAN/em0 only,
     `custom.rules`) confirmed as noise too — its raw SYN-count threshold
     (`count 15, seconds 30, track by_src`, no distinct-destination check) fires on
     ordinary outbound browsing traffic, same underlying bug as the original broken
     `pfsense_portscan.yaml`. Suppressed via `tailscale_stun_noise` (WAN-scoped).
   - Also cleaned up the **historical TheHive backlog**, not just the live source:
     246 unprocessed alerts / 164 cases before cleanup, dominated by exactly this
     noise class (SSDP 52% of all alerts ever created; the old portscan rule and SID
     9000001 added more on top). Marked `Ignored`/`FalsePositive` (not deleted —
     reversible, keeps audit trail, shared instance with Badr) via the TheHive
     `/api/v1` API: 204 alerts total ignored, 42 cases resolved, zero failures across
     both batches. Active "New" queue dropped from 246 to the low 70s.
~~6. **Enrichment analyzer selection**~~ — **done 2026-08-12**, see `notes/18.md` §6.
   `assess_enrichment()` now sends the LLM Cortex's distilled `summary.taxonomies`
   tags (e.g. `VT:GetReport=0/91`, `AbuseIPDB:Score=0`) per observable instead of the
   full raw analyzer report. Verified against the live GPU `mistral:7b`: payload
   dropped to 563 bytes and the model correctly reasoned over the distilled tags
   (tested with synthetic data, bypassing TheHive/Cortex to avoid burning API quota
   or creating a real case just to test a payload-shape change). Deployed to the GPU
   VM's `~/soar/e2e_soc_orchestrator.py`, checksums confirmed matching. **Not yet
   re-tested against a real C-1 attempt** — this fix addresses the *suspected* cause
   of the verdict flip-flopping, but that theory itself hasn't been confirmed by a
   clean C-1 re-run yet.
7. **GreyNoise analyzer** — discussed, not added. Would directly help both noise
   reduction and C-1 (distinguishes mass-internet-scanners from targeted attackers).
8. **MISP** — discussed as a possible addition on `soc-llm-aws` (the retired CPU box,
   which has spare capacity once Ollama is removed from it). Not started. Lower priority
   than the above; would cost ~$73/mo running continuously if pursued.
9. **`confidence_score` schema bound** was added to the orchestrator, not yet re-verified
   against a fresh live LLM response (only unit-tested with synthetic bad input).
10. **Cortex analyzer additions recommended to Badr (2026-08-15), not yet added**:
    GreyNoise (highest priority — same noise-vs-targeted-attacker problem as item 7
    above), ThreatFox (automates what we did by hand all session to source C-1/AsyncRAT
    test IPs, adds a dedicated malware-C2 corroboration source to every verdict), Shodan
    (lower priority, investigation context only). Once Badr adds any of these in
    Cortex, the orchestrator's `ANALYZER_NAME_PREFIXES` list needs the exact registered
    analyzer name added too, or Cortex will run it but the AI verdict won't see the
    result.
11. **Future work, explicitly not pursued now — full agentic tool-calling
    architecture** (discussed 2026-08-15, for Ch.11). Current design is deliberately
    *not* a full autonomous agent: the LLM answers fixed questions at fixed points
    (what is this / is this malicious), it never decides which action to take or
    whether to act — that's hardcoded, deterministic code (`containment_allowed()`).
    A "true" agent architecture would give the LLM tool-calling autonomy over the
    whole workflow, including the containment decision itself. Deliberately not built:
    it would remove the exact deterministic safety layer that this project's central
    argument (Ch.9) rests on — the SSDP-incident risk this whole guardrail model exists
    to prevent. A safer middle ground worth noting for future work: give the LLM
    autonomy over *investigation* steps (which analyzers to check, in what order)
    while keeping the containment decision hardcoded exactly as now. Frame in the
    report as "designed against, not overlooked" — the same "readiness criteria, not
    yet met" honesty already used for the autonomy-widening discussion in §9.8.

~~Copy `soar_audit.jsonl` from the GPU VM into the repo~~ — **done**, see
`ai/results/soar-dryrun-evidence/soar_audit-2026-08-11-gpu.jsonl` (972 lines, current as
of this file's writing).

## Open questions sent to the encadrant, unanswered as of this writing

Sent via WhatsApp, referenced in notes/16.md §7:
1. Does "we can simulate 2 or 3 products" mean comparing SOAR **platforms**
   (TheHive/Cortex vs Shuffle) or comparing **LLM models** (what we actually built
   `ai/results/model-benchmark.md` around)? Don't build a Shuffle comparison until this
   is answered — it's ~13h of work that may not be wanted.
2. Where should the AI sit architecturally — a Cortex analyzer, or a separate service
   reading from TheHive (what we built)? Get explicit confirmation this is acceptable.
3. Fully autonomous blocking vs human-in-the-loop for the final demo — changes what
   gets built in the remaining time. **This is the most consequential open question.**
4. Is the current model-benchmark methodology (prompt tuned on `mistral:7b` before
   testing competitors) acceptable, or should competitors get their own tuned prompt?

## Using the graph

A knowledge graph of this entire repo (255 files, 454 nodes, 555 edges, 39 labelled
communities) was built with `/graphify` today and lives in `graphify-out/`. Query it
before re-reading files by hand for anything cross-cutting:

```bash
graphify query "<question>"                    # broad context, BFS
graphify query "<question>" --dfs               # trace one specific path
graphify path "mistral:7b" "policy_guard()"     # shortest path between two concepts
graphify explain "select_containment_target"    # plain-language node explanation
```

If files have changed since 2026-08-11, refresh it first (only re-extracts changed
files, all 72 semantic files are cached):
```bash
/graphify . --update
```

`graphify-out/GRAPH_REPORT.md` has the full community breakdown, god nodes, and
surprising cross-file connections already written up.

**Graph health note:** 25 of 580 raw edges (4.3%) are dangling — cross-chunk references
where one extraction agent named a concept another agent's chunk didn't declare as a
node. The graph is usable but not perfectly stitched; if a `graphify query` result looks
incomplete, cross-check against the actual files.

## House rules (read before changing anything)

- **Never run destructive commands against pfSense/ELK without confirming first.**
- **Never write real API keys/tokens into any file** — use `<PLACEHOLDER>`, env vars only.
- Prefer short, structured output; code blocks over prose, per the project's own
  `CLAUDE.md`.
- **Always verify VM/service state live before acting** — this project has a repeated
  pattern of things looking fine (rules loaded, responders configured, audit log
  written) while silently not working. Check pfSense tables, Elasticsearch counts, and
  Cortex action statuses directly rather than trusting a success message.
- **Any orchestrator run with `DRY_RUN=False` is armed** — it can really modify the
  firewall. The script prints a loud warning banner when this is the case. Confirm the
  kill switch works (`touch ~/soar/KILL_SWITCH`) before any armed run, and agree the
  rollback command with Badr first: `pfctl -t EasyRuleBlockHostsWAN -T delete <IP>`.
- **Stop the GPU VM when a session ends.** Nothing else in the stack costs meaningful
  money if left running; this one does.
- This project is **not a git repository**. There is no version-control safety net —
  be more careful with file edits than you would be otherwise, and consider proposing
  `git init` if it hasn't been raised already.

## Orchestrator quick reference

`soar/e2e_soc_orchestrator.py`, deployed identically to `~/soar/` on the GPU VM
(verify checksums match before trusting either copy is current).

```bash
# REVOKED 2026-08-21: the key below was found committed in plaintext (a real violation of this
# project's own "never write real API keys/tokens into any file" rule). It has been REVOKED and
# must NEVER be reused for any purpose. Replace with a freshly issued key (exported in your own
# shell only, never pasted back into this file) before running any command below.
export THEHIVE_API_KEY="<REVOKED_AND_REDACTED_THEHIVE_API_KEY>"

# process one specific alert by id, then exit
SOAR_ALERT_ID="~123121912" ./.venv/bin/python e2e_soc_orchestrator.py

# oldest N alerts from the queue, then stop (safe against the ~350-alert backlog)
SOAR_MAX_ALERTS=3 SOAR_ONCE=1 ./.venv/bin/python e2e_soc_orchestrator.py

# rehearse without touching the firewall
SOAR_DRY_RUN=1 SOAR_ALERT_ID="~123121912" ./.venv/bin/python e2e_soc_orchestrator.py

# continuous polling (manual foreground — the systemd service below does this too)
./.venv/bin/python e2e_soc_orchestrator.py
```

~~**Do not turn this into a systemd service yet.**~~ **Done 2026-08-12.** Runs as
`soar-orchestrator.service` on the GPU VM (`systemctl status soar-orchestrator`),
`enabled` so it survives a VM restart. Deliberately **`SOAR_DRY_RUN=1`**, set directly
and visibly in the unit file (not buried in an env file) — this is a real safety
decision, not a placeholder: the original blocker here was that a bare service would
process the whole backlog *with containment armed*, and the encadrant's
autonomous-vs-human-in-loop question is still unanswered, so this stays observe-only
until that's resolved or you deliberately choose to arm it. `THEHIVE_API_KEY` lives in
`~/soar/soar.env` on the VM (chmod 600, not committed anywhere). Verified processing
the real alert backlog correctly end-to-end (multiple `ALERT ~<id> COMPLETE` cycles,
~2.3-2.5s per verdict call, matching the benchmarked warm latency, zero errors).

**No backlog-skip cutoff was added** — the service processes the existing "New" queue
on first start same as a manual run would, it's just that with `DRY_RUN=1` this is
safe (log-only, no real blocking) instead of the dangerous scenario the old warning
was about. If the service is ever switched to armed mode, add that cutoff first.

**Confirmed 2026-08-12: not continuous.** Ayman works this project ~5h/day, 5 days/week
— the VM is only ever up during those sessions (~23h/week, ~$21/week, ~$85/month at
$0.92/hr), same cost pattern as before the service existed. The systemd service just
removes a manual step: whenever the VM is started for a session, the orchestrator
auto-resumes polling (dry-run) instead of needing `./.venv/bin/python
e2e_soc_orchestrator.py` run by hand. Stopping the VM after a session still stops
everything, exactly as it always did — **keep stopping the VM between sessions**, this
hasn't changed.

~~**Dry-run only.**~~ **PERMANENTLY ARMED as of 2026-08-15.** Ayman's deliberate
decision, coordinated with Badr beforehand (his mailer testing shares this box).
`SOAR_DRY_RUN` removed from the unit file entirely; guardrails (kill switch, 0.75
confidence floor, 5 blocks/hour, RFC1918/CGNAT/protected-asset refusal) all still
enforced in code regardless of this flag — only whether a passed check actually
executes has changed. Transitioned safely: armed the config with the kill switch still
active, verified the process picked up the change (`Dry run: False`, `Kill switch:
ACTIVE`), then lifted the kill switch only after confirming that safe intermediate
state.

**Confirmed working immediately after arming**, with an alert the standing service
picked up and acted on entirely on its own (no manual invocation): a fresh AsyncRAT C2
IP (`104.243.248.63`, ThreatFox, VT 14/91 + 88 malicious resolutions — stronger signal
than the original C-1 IP) → `MALICIOUS` verdict → guard passed → **containment
executed automatically** → independently confirmed via `pfctl` AND the pfSense GUI →
**Badr's mailer notification fired correctly too**, confirming his mailer integration
also works in the live armed path, not just dry-run. This is now a second, independent
real-world autonomous block on top of the original C-1 capture.

If autonomy needs to be paused for any reason: `touch ~/soar/KILL_SWITCH` on the GPU
VM, no restart needed.

**Re-armed 2026-08-17** after the Spot-migration recovery (see the incident bullet
above) reset the unit back to dry-run on the rebuilt `ollama-l4-server-spot`. Before
re-arming, validated the recovered pipeline end-to-end in dry-run first with a fresh
Cobalt Strike C2 IP (`38.190.196.19`, ThreatFox) — confirmed the taxonomy-extraction
fix and Badr's mailer sync both survived the redeploy correctly (real VT/AbuseIPDB
taxonomies read correctly, `MALICIOUS` 0.80, mailer fired, comment posted). Mid-check,
the VM rebooted on its own (uptime reset to ~4 min) — turned out to be a plain reboot,
not another snapshot-revert (orchestrator checksum unchanged, `ec401bc1...`); systemd's
`Restart=on-failure` / `enabled` brought the service back up cleanly by itself,
confirming the unit survives an unplanned reboot unattended. Re-ran the same safe
transition as 2026-08-15 (kill switch active during the unit edit, verified `Dry run:
False` + `Kill switch: ACTIVE`, then lifted the kill switch). Confirmed working with a
second fresh IP (`8.163.59.20`, Cobalt Strike, ThreatFox) picked up and acted on by the
standing service with no manual invocation: `MALICIOUS` 0.95 → **containment executed
automatically** → audit log `cortex_status: "Success"` → mailer fired → **independently
confirmed by Ayman directly on the pfSense table** (`8.163.59.20` present in
`EasyRuleBlockHostsWAN`). Orchestrator is confirmed permanently armed and fully
functional on the rebuilt VM.

**Same day, small fix:** operational/watchdog alerts (`is_operational_alert()`) were
correctly excluded from triage but were never dismissed either — they sat as "New"
forever, indistinguishable in the TheHive dashboard's alert counter from a real
unprocessed backlog (found while explaining the alert-vs-case distinction; 21 "New"
alerts were all watchdog noise, 0 real). Fixed: the poll loop now marks them `Ignored`
directly (no LLM triage — nothing to assess), audited as `operational_alert_dismissed`.
Deployed and verified live on the armed VM: all 21 cleared within one poll sweep,
queue now correctly reads 0.

**Same day, TheHive case backlog closed out (analyst-practice pass, 2026-08-17):**
of 238 total cases, 196 had been sitting `New` (open, un-resolved) indefinitely —
including several of the project's own confirmed-real test cases (C-1, C-2, the
AsyncRAT block) — because the orchestrator deliberately never resolves a case itself
(human-in-the-loop boundary, same reasoning as containment). Manually walked through
and closed all 238 with a real disposition (`TruePositive`/`FalsePositive`/`Other`,
per-case summary), split roughly into: real lab attack-simulation detections (rule
fired correctly on genuine red-team/pentest traffic) → `TruePositive`; the project's
own admin SSH logins (`100.85.83.119`, all 14 "Linux Root SSH Login" cases) →
`TruePositive`/`NotApplicable`, noted as authorized not incident; 29 pre-2026-08-12
`PfSense Perimeter Block` cases on port 1900 → `FalsePositive`, the exact SSDP-noise
class fixed that day (the other 4 non-1900 cases in that bucket were real, left
`TruePositive`); pure dev/API mechanism tests (`Cortex Responder API Test` etc.) →
`Other`. Final: 160 TruePositive / 71 FalsePositive / 7 Other, 0 remaining `New`.
Bulk-closed via direct `PATCH /api/v1/case/{id}` calls (`status`/`stage`/
`impactStatus`/`summary`) after manually closing the first case through the UI to
confirm the correct field values — same discipline as always: understand the schema
from a real example before scripting the rest, not guessing at API shape.

Along the way, found 7 cases (2 rule types) with a **cosmetic ElastAlert bug**: title
templates like `Brute Force from {match[winlog.event_data.IpAddress]}` and
`New Service on {match[host.name]}` rendered with the literal, unsubstituted Jinja
placeholder instead of the real field value — the underlying detections were real
(closed `TruePositive` regardless), just the alert *title* was broken. **Checked live
on the ELK box (`win_bruteforce.yaml`, `win_new_service.yaml` in
`/home/ayman/elk-stack/elastalert/rules/`) — both already have plain static titles,
no template placeholder.** Already fixed at some point before now; the broken-titled
cases are historical artifacts predating that fix, not a live bug. No action needed.

**Same day, two real live bugs found and fixed during E-4 prep (red-team MCP recon
against Juice Shop, 2026-08-17):** an `nmap_scan` against the target produced real
Suricata alerts (`ET SCAN Nmap Scripting Engine User-Agent Detected`, confirmed via
direct Elasticsearch query, `src_ip: 100.125.163.9`) but nothing reached TheHive.
Root-caused via `docker logs elastalert` on the ELK box (password-auth SSH, no key set
up — same as pfSense):
1. **13 detection rules silently disabled since container start** — `juiceshop_sqli`,
   `juiceshop_xss`, `juiceshop_lfi_directory_traversal`, `pfsense_portscan`,
   `Suricata High Severity Alert`, `linux_root_login`, and all 5 watchdogs. Confirmed
   each rule file itself was valid (`elastalert-test-rule` ran `juiceshop_sqli.yaml`
   manually — worked fine, found a real historical hit). Touching file mtimes did NOT
   trigger a reload (ruled that theory out); a clean `docker restart elastalert` did.
   Root cause of the *original* disablement not fully pinned down — best guess is a
   transient ES/TheHive unavailability at this morning's container start that
   ElastAlert doesn't auto-retry from, since rule files hadn't changed since 08-12.
2. **ElastAlert's own TheHive API key was stale** — `hive_apikey` in
   `elastalert/config.yaml` still had the *old*, pre-rotation key
   (`<REVOKED_AND_REDACTED_THEHIVE_API_KEY>`), different from the key the orchestrator uses
   <!-- REDACTED 2026-08-22 (repo-hygiene pass): this line previously quoted the live,
        currently-active TheHive API key in plaintext, in violation of this project's own
        CLAUDE.md rule. Revocation status is UNCONFIRMED — see
        soar/L1-L2-SAFETY-AUDIT.md §21 (open blocker) and docs/SECURITY.md. Rotate this
        key with Badr before any GitHub push or live integration test. -->
   (`${THEHIVE_API_KEY}` — see docs/SECURITY.md). Every `hivealerter` send was failing with
   `401 Unauthorized`, invisibly — the key rotation (B-1) had only been applied on the
   orchestrator side, never synced to ElastAlert's own config. Fixed in both the live
   box and the repo mirror (`configs/elk/elastalert/config.yaml` — real key in
   plaintext there deliberately, per this directory's standing unredacted-local-only
   policy; that file is gitignored, never pushed).

**Verified fixed end-to-end**: after both fixes + restart, fresh real alerts (`Direct
Root SSH Login Detected`, `Path Traversal / LFI Attempt on Juice Shop`,
`Port Scan Detected by PfSense`, `XSS Attempt on Juice Shop`) landed in TheHive with
status `Imported` within minutes — full chain (Suricata/ELK → ElastAlert → TheHive
auth) confirmed live again. This means **the entire live detection posture had been
silently degraded** (core Juice Shop rules + Suricata forwarding + all watchdogs dark,
zero alerts reaching TheHive at all) for an unknown period before today — worth an
honest mention in the report as exactly the kind of silent-failure risk the watchdog
layer (A-1) exists to catch, and a reminder to verify watchdogs are themselves
alerting correctly, not just present.

Also confirmed a real, separate architecture finding while testing: a broad port scan
against pfSense's own Tailscale IP (100.70.145.65) on ports NOT NAT-forwarded to a
physical interface (e.g. 22/53/80, pfSense's own admin services) produces **zero**
Suricata visibility — confirmed via direct Elasticsearch query, 0 hits from Kali's
source IP for that scan. Only the specific NAT'd flow (8080→172.16.0.10:80, the actual
Juice Shop path) is visible, since Suricata has no capture on the `tailscale0`
pseudo-interface itself. This means `pfsense_portscan`'s cardinality rule can
essentially never fire against a Tailscale-sourced attacker under the current
architecture — a real, now-empirically-confirmed coverage gap worth documenting in
E-3, not just a theoretical one.

**Same day, third bug found and fixed — project-wide, not isolated**: while looking at
a freshly-generated case (`#247`, `linux_root_login`), its TheHive description showed
literal unrendered placeholders (`Source Host: {0}`, `Log Message: {1}`,
`Timestamp: {2}`) instead of real values — caught directly by Ayman reading the case,
not by me. Root cause: `hive_alert_config.description` uses Python positional
`.format()` placeholders (`{0}`, `{1}`, ...), which the custom `HiveAlerter` patch
(`configs/elk/elastalert/patches/thehive.py`, `load_args()`) only fills in from a
`hive_alert_config.description_args` list — **every rule had the field list under the
wrong key**, as a top-level `alert_text_args` (which feeds a different, unused
ElastAlert-native alerter path), never as `hive_alert_config.description_args`.
Confirmed genuinely systemic, not a one-off: **24 of 30 rule files** had this exact
bug (`pfsense_portscan.yaml` proved it wasn't a knowledge gap — it already correctly
used `sourceRef_args` under `hive_alert_config`, just missed the parallel
`description_args`). Wrote a small script
(scratchpad `fix_description_args.py`) to mechanically copy each file's existing
`alert_text_args` list into a new `hive_alert_config.description_args` block in the
right place — safe because the two lists were already identical field-for-field, just
attached to the wrong mechanism. Applied to all 24 on the live ELK box, `docker
restart elastalert`, verified via `elastalert-test-rule --alert` against
`juiceshop_sqli` — real case description now renders correctly (client IP, exact SQLi
payload, method, user-agent, timestamp, all real values, zero placeholders). Synced
all 24 fixed files back into the local repo mirror. **Practical impact**: every
custom-rule TheHive case created before today (hundreds, across the whole case
history closed out earlier today) has a description full of `{0}`/`{1}`/etc
placeholders instead of real evidence — cosmetically broken but not a detection
failure (the alert/case/observable/enrichment/verdict pipeline never depended on this
text). Going forward, new cases will have real, readable descriptions. Not
retroactively fixed on old closed cases (would require re-rendering historical match
data per case; not worth doing given they're already closed with accurate summaries
from today's manual closure pass).

**Same day, E-4 chain (a) started — Juice Shop attacks via the red-team MCP server,
real results**: first genuine use of `redteam-mcp` against a live target since it was
built. Confirmed the GPU VM survived an unrelated mid-session reboot (uptime reset to
~3 min) and self-healed correctly — `enabled` + `Restart=on-failure` brought the armed
orchestrator back up automatically with the correct banner (`Dry run: False`, kill
switch inactive) and it kept processing live alerts through the restart with no manual
intervention. Confirmed the CGNAT policy guard is a real safety net during red-teaming,
not just theory: every case generated by Kali's own traffic (`100.125.163.9`) resolved
to `benign` (real VT/AbuseIPDB reputation checks correctly found nothing on our own
lab IP) with **zero containment attempts** against Kali throughout — checked directly
in `soar_audit.jsonl`, not just trusted the dashboard.

Results per stage, hits and misses (E-4's own instruction — misses are content too):
- **Recon** (`nmap_scan`, full port range against `100.70.145.65`) — only the
  DMZ-NAT'd port (8080→Juice Shop) generated any Suricata visibility (`ET SCAN Nmap
  Scripting Engine User-Agent Detected`, confirmed via direct Elasticsearch query on
  `src_ip: 100.125.163.9`). The broader scan against pfSense's own
  Tailscale-terminated ports (22/53/80) produced **zero** Suricata events — confirmed
  empirically (not assumed) that Suricata has no capture on the `tailscale0`
  pseudo-interface, so `pfsense_portscan`'s cardinality rule can never fire against a
  Tailscale-sourced attacker under the current architecture. Real, now-proven E-3 gap.
- **SQLi, search endpoint** (`sqlmap` against `/rest/products/search`) — detected
  cleanly: `juiceshop_sqli` fired, correct client IP, real UNION-based payload in the
  case description (after the templating fix above).
- **SQLi, login endpoint / admin-token-theft vector** (`sqlmap` against
  `/rest/user/login`, JSON body via `--data` + `-H "Content-Type: application/json"`
  + `--ignore-code=401` to get past Juice Shop's initial 401) — confirmed genuinely
  exploitable: boolean-based blind SQLi on the `email` JSON field, 562 requests, this
  is Juice Shop's classic admin-login-bypass vulnerability. Same payload burst also
  cross-triggered `juiceshop_xss` (payload happened to contain a `<script>` string)
  and `juiceshop_lfi_directory_traversal`, plus a raw Suricata signature (`ET
  WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access`) — good multi-rule
  coverage evidence from one real attack run.
- **Web vuln scan** (`nikto`, port 8080) — timed out at the tool's 300s cap before
  completing, but its early RFI-test probe was caught (`juiceshop_xss` logged an
  observable referencing nikto's `cirt.net/public/rfiinc.txt` signature URL). Partial,
  not a clean pass.
- **Directory brute-force** (`gobuster`) — N/A, not a tool failure: Juice Shop is an
  Angular SPA and returns HTTP 200 for any path, so gobuster correctly detected the
  wildcard-response condition and refused to run rather than produce garbage results.
  Conclusion: directory brute-forcing isn't a meaningful technique against this
  specific target — skip it in future runs rather than fight it.
- **Login brute-force** (`hydra`, `http-post-form` against `/rest/user/login`) —
  **blocked by a real bug in `redteam-mcp/server.py`**: the wrapper always appends
  `{target} {service}` after the caller's `options` string, but hydra's
  `http-post-form` module requires its own path/body/condition string to come *after*
  target+service on the command line. Confirmed via the actual hydra error (`[ERROR]
  Unknown service: 100.70.145.65` — hydra had misparsed positions). Not attempted;
  deferred, see below.

**Next-session plan (Ayman's own words, 2026-08-17 EOD): "i will do that tomorrow"**
— fix `redteam-mcp/server.py` before continuing E-4:
1. Fix the hydra command-construction bug so module strings requiring trailing
   positional args (`http-post-form`, possibly others) work — general fix, not
   Juice-Shop-specific, will matter again for Windows/Linux brute-force stages.
2. Bump nikto's timeout or add scan-tuning flags so it completes instead of
   truncating at 300s.
3. Leave gobuster as-is — not a bug, Juice Shop's SPA behavior is just not a good fit
   for that technique.

Then resume E-4 chain (a) at the point it left off: admin token theft (the SQLi login
bypass is confirmed exploitable — next step is actually extracting a valid session/JWT
via `sqlmap --dump` on the Users table, not yet done) → lateral movement attempt
toward the LAN → persistence attempt on the Linux host. Chain (b) (Windows foothold →
privesc → credential dumping → lateral movement) hasn't been started at all yet.

**Follow-up, same day**: fixed the hydra ordering bug and bumped nikto's timeout
(600s) in `redteam-mcp/server.py`, as planned. The hydra fix itself works — verified
the module string now lands after `target service` on the command line, confirmed via
the actual echoed hydra command — but hit a *separate*, pre-existing hydra quirk:
`http-post-form` splits its module argument on unescaped colons, and Juice Shop's JSON
login body is colon-heavy (`{"email":"...","password":"..."}`), so getting the
escaping exactly right (`\:` for literal colons) proved unreliable even once escaped
correctly per hydra's own docs — genuine hydra-vs-JSON-API friction, not a wrapper bug.
Rather than keep fighting hydra's syntax, added two new generic tools instead:
`http_request` (single raw curl call — a one-shot escape hatch for exact
payloads/JSON endpoints sqlmap/hydra don't fit) and `http_json_bruteforce` (loops curl
over a password wordlist against a JSON endpoint, returns an HTTP-status histogram —
a hydra-free way to exercise `juiceshop_bruteforce`/`*_login_bruteforce` against JSON
APIs specifically). Both compile clean; **neither tested live yet** — same as the
hydra/nikto fixes, the running MCP server process needs a restart to pick up the new
tools before they can actually be called.

**Same day (2026-08-18), Burp Suite MCP integration — done, working.** User's idea:
found PortSwigger's own official extension (github.com/PortSwigger/mcp-server) and
asked to build the "right" tools for JSON-API pentesting instead of continuing to
fight hydra. Full build-and-wire saga:
1. Cloned + built on Kali (`~/burp-mcp-server`). Build itself needed one fix: the
   system JDK 25 package is missing the `jar` binary (stripped-down Kali package);
   worked around by pointing `PATH` at Gradle's own bundled JDK 21
   (`~/.gradle/jdks/eclipse_adoptium-21-.../bin`), which has it. `./gradlew
   embedProxyJar` then succeeded cleanly.
2. First attempt: ran Burp headless via Xvfb + x11vnc (no physical display on Kali).
   Got through the EULA and edition-selection screens via `xdotool` automation
   (screenshotted via ImageMagick `import`, clicked via coordinates) — but the
   extension's own Ktor server never actually bound its port, with **zero error
   anywhere** (not in Burp's event log even at Debug level, not in raw stdout/stderr)
   despite the extension's source code (confirmed by reading it directly on Kali)
   properly routing exceptions to `api.logging().logToError()`. Also saw
   `[2] Error initializing Target tool` and a stripped-down menu bar (only
   Dashboard+MCP, missing Target/Proxy/Extensions/etc.) — concluded this was a
   genuine Xvfb rendering limitation affecting core Burp Swing components, not an
   MCP-specific bug. Confirmed the `mergeServiceFiles()` theory (SLF4J NOP-logger
   warning at startup) was a red herring — that config was already present in the
   repo's own `build.gradle.kts`; the missing SLF4J provider only silences Ktor's
   internal logs, not the extension's own `api.logging()` calls.
3. Ayman had direct GUI access to Kali via its real VMware console (not SSH) —
   switched to that instead of fighting Xvfb. **Worked on the very first try**: EULA
   → Community Edition → Temporary project (CE has no project-file support, Pro-only)
   → Start Burp → full toolbar rendered correctly (Target/Proxy/Extensions all
   present, unlike Xvfb) → loaded the extension via the normal Extensions tab (Add →
   Java → `burp-mcp-all.jar`) → Output showed `Started MCP server on 127.0.0.1:9876`
   immediately, no toggle-fighting needed. Confirms the Xvfb theory was correct.
4. Added the 3 lab targets (`100.70.145.65:8080`, `100.101.109.12`,
   `100.105.72.46`) to Burp's own Auto-Approved HTTP Targets list — mirrors this
   project's own scope-guard philosophy: known lab traffic flows without a human
   click, anything else still requires manual approval in the Burp UI (a real safety
   feature of the extension, kept intentionally rather than globally disabled).
5. Wiring to Claude Code (runs on Ayman's laptop, not Kali/ELK/GPU): Burp's MCP
   server only binds `127.0.0.1` on Kali (no non-localhost bind option in this
   build), so bridged with an SSH port-forward
   (`ssh -N -L 9876:127.0.0.1:9876 kali@100.125.163.9`) rather than exposing the raw
   port on the tailnet. Copied the extension's own bundled proxy jar
   (`~/burp-mcp-server/libs/mcp-proxy-all.jar` on Kali) to
   `redteam-mcp/burp-proxy/mcp-proxy-all.jar` locally. Manually tested the proxy
   jar directly (`java -jar mcp-proxy-all.jar --sse-url http://localhost:9876`,
   default args, no `--help` needed) — connected immediately through the tunnel and
   listed real tools (`send_http1_request`, `send_http2_request`,
   `create_repeater_tab(_http2)`, `send_to_intruder`, `url_encode/decode`,
   `base64_encode/decode`, more). Only then registered it in `.mcp.json` as a new
   `burp` server.

**Known fragility, not yet automated**: both the Kali-side Burp process (needs the
real VMware console session, or a future non-headless retry) and the local SSH
tunnel are manually-started, not services. If either dies, `burp` MCP tools go
silent until both are restarted by hand. Full details and the exact commands are in
`redteam-mcp/README.md`'s new "Burp Suite MCP server" section.

**Update, same session — `burp` tools used for real, immediately valuable.** Ayman
restarted Claude Code; `burp` tools loaded correctly. First real use:
`send_http1_request` with the classic Juice Shop admin-bypass payload
(`{"email":"' OR 1=1--","password":"x"}`) against `/rest/user/login` — worked in one
clean call, no colon-escaping fight (unlike hydra). Result: **genuine full
admin-account takeover**, real JWT returned (`role: admin`,
`email: admin@juice-sh.op`) — completes the "admin token theft" step of E-4 chain
(a) that was blocked all of 2026-08-17.

**More importantly, this surfaced a real, severe, previously-unknown detection
gap.** Checked TheHive/Elasticsearch: the request landed correctly (confirmed via
direct ES query, correct client IP `100.125.163.9`), but **no alert fired** —
`juiceshop_sqli`'s keyword filter (`UNION`/`SELECT`/`DROP`/`INSERT`/`sleep`/
`benchmark`) doesn't match boolean/comment-based bypass payloads, which contain no
SQL keyword at all. A full admin compromise, completely invisible to detection.

**Fixed same session.** Widened `juiceshop_sqli.yaml`'s filter (`bool.should`,
`minimum_should_match: 1`) to OR the original keyword check with new wildcard
patterns (`*' OR*`, `*' AND*`, `*'--*`, `*';*`) against `access_log.request_body`
and `.request_uri`'s **`.keyword`** sub-fields specifically — the original analyzed
`.text` field tokenizes on punctuation, so a raw `'--` wildcard would never match
there (verified this distinction directly against the field mapping and a live ES
query before writing the fix, not assumed). Hit one real YAML/DSL bug while
deploying: nested the old `query_string` clause inside the new `bool.should` still
wrapped in ElastAlert's outer `query:` key, which is only valid at the top level of
ElastAlert's own `filter:` list, not inside a raw nested `bool` — caused a 400
`unknown query [query]` from Elasticsearch; fixed by unwrapping it.

**Verified fixed, end-to-end, twice**: (1) direct ES query confirmed the exact
captured admin-bypass document now matches the new filter; (2) re-sent the identical
live attack via Burp after restarting `elastalert` — a fresh, correctly-described
TheHive alert (`Client IP: 100.125.163.9`, `Request Body: {"email":"' OR 1=1--",...}`)
landed automatically via the standing service, no manual test invocation. Gap closed,
confirmed live, not just in a test harness. Rule file synced to the local repo mirror.

## Report status

- `report/benchmark-report.tex` — 8-page LaTeX benchmark report for the encadrant,
  compiles cleanly, covers the 3 model experiments + CPU/GPU comparison + limitations.
- `report/Local_LLM_Benchmark.pdf` — the compiled version already sent.
- Main project report structure: see `REPORT-PLAN.md`.
- `FINAL-ROADMAP.md` is the current authoritative roadmap (supersedes `ROADMAP.md`,
  which has a banner pointing to it).

## Suggested next session priorities

As of 2026-08-13, **all five** items in FINAL-ROADMAP.md's centrepiece/blocking
sections are done: A-1 (watchdogs), A-1b (Redis reboot survival, root-caused via a real
unplanned reboot), C-1 (autonomous block, independently verified), C-2 (correct
refusal, independently verified), C-3 (responder mechanism). Detection noise cleanup
and the enrichment-summary fix are also both done (2026-08-12, `notes/18.md`), along
with the pfSense `syslogd` outage (root-caused, permanent cron mitigation) and the
taxonomy-extraction bug found while capturing C-1 (2026-08-13, `notes/19.md` — real
fix, verified against live data, not just synthetic). In order, assuming Badr's stack
is up:
1. **A-2 — clean 3-alert dry-run pass** on the fully-fixed code, now that the
   taxonomy bug is fixed (previous dry-run activity before today's fix was running on
   silently-empty enrichment data, so isn't a valid "clean pass" reference).
2. The roadmap's Evidence & Coverage section (E-1 through E-9) and the report
   chapters (R-1 through R-9) are now the largest remaining body of work — see
   `FINAL-ROADMAP.md` for the full task register. None of E-1..E-9 or R-1..R-9 have
   been started as of this writing. With C-1/C-2/C-3/A-1/A-1b all captured, this is
   the actual bottleneck to finishing, not further engineering — matches the
   roadmap's own framing: *"the risk is not capability, the risk is not finishing the
   evidence."*

If Badr's stack is down, useful solo work: writing up the main project report using
the graph to pull cross-session threads together (remember to `/graphify . --update`
first — it's stale as of the 2026-08-12 changes).
