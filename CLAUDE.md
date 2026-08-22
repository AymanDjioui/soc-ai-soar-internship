# Project: SOAR + AI for SOC Detection (Devoteam internship)

## Ownership
- Me (Djo/Ayman): ELK stack, pfSense config, Suricata, Elastalert2→TheHive bridge
- Badr: TheHive/Cortex (AWS), Cortex responder auto-block, network segmentation (WAN/LAN/DMZ), Juice Shop victim

## Current architecture (updated — DMZ added)
- pfSense zones: WAN (VMnet8/NAT), LAN 192.168.10.0/24, DMZ 172.16.0.0/24
- Juice Shop (Alpine) in DMZ at 172.16.0.10, reachable externally via Tailscale-interface
  NAT port-forward 8080 → 172.16.0.10:80
- Suricata runs on **three** interfaces: wan (em0), lan (em1), and opt1/DMZ (em2). The
  wan+DMZ pair was confirmed 2026-07-16 via pfSense config.xml + live eve.json alert
  (SID 2009714, src 100.101.27.63 → dest 172.16.0.10:80 via Tailscale NAT
  100.70.145.65:8080), verified end-to-end in suricata-alerts-2026.07.15 in
  Elasticsearch. Gap is closed — DMZ-facing capture sees Tailscale-sourced attacks
  post-NAT. No Suricata instance on the Tailscale interface itself (pseudo-interface,
  device tailscale0), but not needed given DMZ coverage. **The lan (em1) instance went
  undocumented until 2026-08-12** — found while debugging a suppress-list change that
  had no effect on alert volume because all the traffic was actually on em1, not
  wan/DMZ. See `notes/18.md` and `PROJECT-STATE.md`.
- MIGRATED 2026-07-16: Suricata EVE delivery moved from `tail|nc` file forwarder to
  **native Redis output** (Suricata → Redis list `suricata` on pfSense:6379 → Logstash
  `redis` input). More reliable (no dropped events on TCP hiccup, no PID-watching cron
  needed). pfSense's Suricata package has no Redis-auth field in its GUI — Redis runs
  unauthenticated (`protected-mode no`), access controlled only via a pf firewall rule
  scoping port 6379 to the ELK VM's Tailscale IP (100.99.54.59). Old forwarder script/
  cron entry retired. Logstash's 5515(udp)/5516(tcp) inputs removed as dead code.
- RESOLVED (2026-07-16, later same day): Badr brought Juice Shop back up. Re-verified full
  chain live: curl XSS probe from djioui (100.85.83.119) → Tailscale 100.70.145.65:8080 →
  NAT → 172.16.0.10:80 → Suricata em2 alert (SID 2009714) → Elasticsearch, ~5s end-to-end.
  Note: DMZ eve.json only grows when there's actual DMZ traffic — an apparently "frozen"
  file just means no traffic, not a broken Suricata instance. Don't mistake one for the other.
- Local config mirror: `configs/pfsense/` (config.xml, suricata_forward.sh, rc.conf.local)
  and `configs/elk/` (docker-compose.yml, .env, logstash/, elastalert/) — pulled via SSH
  over Tailscale, kept unredacted per user decision (contains live secrets/passwords —
  do not publish/share this folder externally).
- ELK 8.15.0 @ 100.99.54.59, Elastalert2 2.19.0 → TheHive (AWS, devoteam-soc org)
- TheHive → Cortex → Flask webhook (AWS) → SSH → pfSense easyrule block (Badr, working)
- AI layer (NEW 2026-08-04): local LLM for triage, `mistral:7b` via Ollama on
  `soc-llm-aws` (my own AWS account, EC2 `m7i-flex.large`, eu-north-1), joined to
  Tailscale as `soc-llm-aws` (100.96.231.95). Not on my laptop (tested there first,
  reversed — running alongside the ELK VM + browser dashboards saturated host RAM/swap
  and contributed to a host hang). Ollama bound to `0.0.0.0:11434` but only reachable
  over the tailnet in practice (security group: admin-IP SSH only, no public 11434).
  **Must be manually started** in the AWS console before use — stopped between
  sessions for cost control, no auto-start, public IP changes on each stop/start so
  always connect via the Tailscale IP, not the public one. Model choice + prompt
  (few-shot, enum-constrained MITRE schema, 90% on a 7-case golden set) benchmarked
  against 4 other models — see `ai/results/model-benchmark.md`,
  `ai/results/deployment-latency.md`, `notes/13.md`. Workflow layer (Shuffle vs. a
  small Python service, TheHive integration) not yet built — ROADMAP Track B2+.
- **MIGRATED to GPU 2026-08-10: the AI layer now runs on `ollama-l4-server`** (my own
  GCP account, `g2-standard-4` + **NVIDIA L4 24 GB**, europe-west4-c), Tailscale
  `100.90.228.58`. Ollama bound `0.0.0.0:11434`, model 100% GPU-resident. Orchestrator
  deployed at `~/soar` (venv, user `djiouiayman`). **Tailscale SSH is enabled** — no key
  setup needed, GCP firewall blocks public :22 by design, so always connect over the
  Tailscale IP. Same `mistral:7b` digest `6577803aa9a0` as the CPU hosts.
  **Warm triage 2.5 s vs 177.6 s on EC2 CPU — 71x.** Cold start is 37.7 s (VRAM load),
  so warm the model before any demo. See `ai/results/deployment-latency.md` §6.
  `soc-llm-aws` (EC2 CPU) is **stopped, not terminated** — kept as the CPU baseline for
  the report's hardware comparison and as a fallback.
  Cost: ~$0.92/hr — **must be stopped between sessions** (a week left running is ~$150).
- T4 GPUs were unobtainable (capacity errors in 4 regions); L4 was available at once.
  Don't burn time chasing T4.

## Rules
- Never run destructive commands against pfSense/ELK without confirming first
- Never write real API keys/tokens into any file — use <PLACEHOLDER>
- Short, structured output. Code blocks over prose.