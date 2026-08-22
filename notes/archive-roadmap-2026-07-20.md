# Roadmap — Remaining Internship Work

Last updated: 2026-07-20. Internship ends **2026-08-31** — 42 days left (11 in July,
all of August). Task-by-task, not calendar-based — move to the next item when the
current one is actually validated with live evidence, not on a fixed schedule, but
keep an eye on the real deadline: Task 7's demo dry-run needs to land with buffer
before 08-31, not on it.

## Where we actually stand right now

- **Network IDS (Suricata, WAN+DMZ)**: working, alerting into `suricata-alerts-*`, IDS
  dashboard built.
- **Juice Shop (DMZ web target)**: full traffic + security dashboard built, 7 attack
  scenarios validated end-to-end (4 caught at network/IDS level, 3 caught only at
  app-layer — brute force, IDOR, SQLi auth bypass with confirmed full account takeover).
- **TheHive/Cortex + auto-block** (Badr, Phase 1): working — this is the SOAR foundation
  everything in the AI section below plugs into.
- **Linux LAN host** (`192.168.10.20`): syslog flowing into `linux-lan-logs`, confirmed
  live in Discover. No dashboard or alerting built on it yet.
- **Windows LAN host** (`192.168.10.30`): Winlogbeat flowing into `lan-windows-logs`,
  real Security event log data (logons, privilege use, account management). No
  dashboard, no Sysmon, no alerting yet.
- **Suricata on the LAN interface (`em1`)**: done — capture confirmed 2026-07-24,
  genuine signature-match alerting confirmed 2026-07-28 (see notes/12.md). Found and
  fixed a real gap along the way: `em1`'s compiled ruleset had silently lost its
  category selection (389 lines vs DMZ's 51,051) despite the GUI setup, so it could
  capture traffic but never actually alert. Re-selected categories via GUI, confirmed
  fixed.
- **Not started**: everything in the SOAR/AI section below. This is genuinely new
  ground for both of us — detailed on purpose.

---

## Task 1 — Linux LAN host: dashboard + validated detections

- Build a Kibana dashboard: auth success/fail over time, sudo usage, new user/group
  creation, cron/systemd activity — same panel pattern as the Juice Shop dashboard
  (a couple of volume panels + a couple of behavior panels).
- Run real attacks and confirm each shows up:
  - SSH brute force (`hydra` or a simple loop of failed logins)
  - Privilege escalation attempt (misconfigured sudoers entry, or a known local PE
    if the box is intentionally vulnerable)
  - Persistence via cron entry or systemd timer/service
- **Do not SSH into or otherwise touch this VM without first confirming access with
  Badr** — same standing constraint as before.

## Task 2 — Windows LAN host: Sysmon + dashboard + validated detections

- Install **Sysmon** (currently only Winlogbeat/Security log — Sysmon adds process
  creation, network connections, registry changes; without it, most real attack
  techniques are invisible, you only see logons).
- Build a dashboard: logon events, privilege use, process creation (once Sysmon is
  in), PowerShell activity if script-block logging is enabled.
- Run real attacks and confirm detection:
  - Credential-dumping simulation (Mimikatz or a safe equivalent)
  - Suspicious PowerShell execution (encoded command, download cradle pattern)
  - Persistence mechanism (scheduled task or run key)

## Task 3 — Suricata on the LAN interface (`em1`) — ✅ DONE (2026-07-28)

- Same pattern as the existing WAN(em0)+DMZ(em2) setup. Closes the last
  network-blind-spot — right now the two new LAN hosts have zero network-layer
  visibility, only host logs. Low effort, closes a real gap.
- Closed out: capture confirmed 2026-07-24, genuine alert-signature match confirmed
  2026-07-28 from both LAN hosts after fixing a silent rule-category gap. See notes/12.md.

## Task 4 — MITRE ATT&CK use-case catalog

- One table: technique → target (Juice Shop / Linux / Windows) → detected by →
  evidence (screenshot/query). Backbone of the final report. Update it as each task
  above is validated, not all at once at the end.

## Task 5 — Red-team attack chains

- Stop testing one attack at a time. Run 2-3 multi-stage chains spanning MITRE
  tactics across the three targets, e.g.:
  - Recon (scan) → initial access (Juice Shop SQLi) → credential theft (admin
    token) → lateral movement attempt toward LAN hosts → persistence on Linux host.
  - Initial foothold on Windows → privilege escalation → credential dumping →
    lateral movement toward Linux/Juice Shop.
- Document what got caught and what didn't **at each stage** — gaps found here are
  genuinely valuable report content, not something to hide.
- Close the quick-win gaps; document the rest as known limitations.

---

## Task 6 — SOAR + AI-assisted triage (the core new work, detailed)

This is new territory, so this section explains the *why* and *how*, not just a
checklist. The existing TheHive/Cortex/auto-block loop (Phase 1, Badr) already does
**S**ecurity **O**rchestration — rules fire, cases get created, one responder
auto-blocks an IP. What's missing is the two things that make it "AI-SOAR" rather
than just "SOAR": (a) more automated *response* actions beyond block-an-IP, and
(b) an AI layer that reads an alert and helps a human triage it faster.

### 6.0 — Which LLM: self-hosted open model, not a cloud API, not training from scratch

Two options were on the table — a cloud LLM API, or training our own model. Training
a model from scratch is not realistic in the time left: it needs a large labeled
security dataset (we don't have one), GPU compute, and weeks of ML pipeline work
just to get a first result — that's a separate multi-month project on its own, not
something to bolt onto the last weeks of this one.

The right middle ground is a **self-hosted open-weight LLM via Ollama**
(ollama.com — runs locally, one command to pull and serve a model, exposes a local
HTTP API on port 11434 that looks almost identical to any other LLM API). No
training, no dataset needed — just prompting a model that's already
instruction-tuned, the same way you'd prompt any hosted LLM, except it runs on our
own hardware:

- **Fits the project's own pattern**: everything else here (ELK, TheHive, Shuffle)
  is self-hosted — a locally-run LLM is consistent with that, not a new kind of
  dependency.
- **Data stays in-house**: security incident data (attacker IPs, payloads, internal
  hostnames) never leaves our network to a third-party API — a real, citable point
  for a SOC report, not just a cost-saving detail.
- **No API key/billing to manage** — one less moving part while learning this for
  the first time.
- **Model choice**: start with a mid-size instruction-tuned model that runs
  reasonably on a normal VM/laptop CPU (no GPU required, just slower) — e.g.
  `llama3.1:8b` or `mistral:7b` via `ollama pull`. If responses are too slow or too
  weak, step up in size later; don't over-optimize the model choice before the
  triage flow itself works end-to-end.
- **Where it runs**: on the ELK VM (or its own VM if resources are tight), reachable
  from Shuffle over the local network/Tailscale, same as every other internal
  service in this project.

If there's spare time at the very end (Task 7's buffer), *fine-tuning* this local
model on a handful of our own real alert→triage examples is a legitimate stretch
goal and a great report addition — but it's explicitly optional, after the base
flow works, not a blocker.

### 6.1 — Concepts first (read this before building anything)

- **SOAR** = when an alert fires, instead of a human doing everything by hand
  (read alert → decide severity → look up IP reputation → decide response → act →
  document), some of those steps run automatically. TheHive is the *case
  management* layer (tracks the incident), Cortex is the *responder/analyzer*
  layer (runs actions — enrichment lookups, or active responses like blocking).
- **Why bring in Shuffle instead of hand-writing a script**: Shuffle
  (shuffler.io, open-source, self-hosted via Docker) is a visual workflow-automation
  engine built specifically for SOC use — it already has ready-made "apps" (nodes)
  for TheHive, Cortex, Elasticsearch/OpenSearch, HTTP requests, and webhooks, plus
  built-in scheduling, retry logic, execution history/logging, and conditional
  branching. Instead of writing and babysitting a Python polling script, you build
  a **workflow**: drag a trigger node, drag an HTTP/app node for each step, connect
  them, and Shuffle runs it and shows you every execution with full input/output —
  which is also a much stronger thing to demo live than a terminal running a
  script. This is the "automate all the things" tool: once this pattern exists, new
  automations (auto-disable an account, auto-enrich with an IP reputation lookup,
  auto-isolate a host) are new Shuffle workflows, not new scripts.
- **What "AI-assisted triage" concretely means here**: a Shuffle workflow watches
  for new TheHive alerts/cases, sends the alert data + the raw underlying event
  (e.g. the actual Suricata JSON or the Juice Shop log line) to the local LLM
  (Ollama, see 6.0), and asks it to produce four things:
  1. A plain-language summary of what happened
  2. A suggested severity/priority
  3. A suggested MITRE ATT&CK technique ID
  4. A first-pass response recommendation
- The workflow posts that output back onto the TheHive case as a **comment or
  task**, not as an automatic action. A human analyst still reads it and decides.
  This is the honest, defensible scope: "AI drafts, analyst decides." Keep any
  workflow branch that *auto-executes* something (block IP, disable account,
  isolate host) as a **separate downstream step gated by the human's decision**,
  not something the AI's output triggers directly.

### 6.2 — Architecture (what you're actually building, as a Shuffle workflow)

```
[Trigger node] — Shuffle webhook, called by a TheHive "responder"/webhook
   configured to fire on new-case-create (TheHive supports outgoing webhooks;
   this replaces the "polling script" idea entirely — Shuffle exposes a webhook
   URL you paste into TheHive's config)
        |
        v
[HTTP node] — GET the full case + observables from TheHive's REST API
   (GET /api/v1/case/{id}), using a TheHive API key stored in Shuffle's own
   secrets/variables store (never hardcoded in the workflow)
        |
        v
[HTTP node] — query Elasticsearch for the raw source event (the Suricata alert
   doc or the juiceshop-docker access_log doc), using the case's timestamp/IP as
   the correlator
        |
        v
[HTTP node] — call the local Ollama API (`POST http://<ollama-host>:11434/api/generate`,
   or `/api/chat`) with the prompt template (6.4), case data + raw event
   substituted in, asking for structured JSON back
        |
        v
[Condition/regex node, optional] — validate the model returned well-formed JSON;
   branch to a retry or a "flag for manual review" path if not
        |
        v
[HTTP node] — POST back to TheHive: /api/v1/case/{id}/comment (or /task) with
   the formatted output, prefixed "🤖 AI Triage Draft —" so no analyst mistakes
   it for a human note
```

Every node above is either a built-in Shuffle "HTTP" app (generic REST call) or,
if available, the dedicated TheHive app from Shuffle's app store — either works,
the dedicated app just saves you re-typing auth headers on every node.

### 6.3 — Where this runs

- **Deploy Shuffle itself** via Docker Compose on the ELK VM (or its own small VM
  if you'd rather isolate it) — Shuffle publishes an official `docker-compose.yml`.
  It needs network access to: TheHive (AWS, over Tailscale), Elasticsearch (local),
  and the Ollama host (local/Tailscale — no public internet dependency at all for
  the LLM step, unlike a cloud API). Give the Shuffle host its own Tailscale
  identity so it can reach TheHive the same way everything else in this project
  does.
- **Deploy Ollama** (`ollama serve`, or its own Docker container — an official
  image exists) on the ELK VM or a dedicated VM, `ollama pull llama3.1:8b` (or
  `mistral:7b`) once, then it's ready to serve requests on port 11434.
- **Secrets**: store the TheHive API key in Shuffle's built-in variable/secrets
  store (Admin → Organization → Variables, referenced in workflow nodes as
  `$variable_name`), not typed directly into node fields — the Ollama endpoint
  needs no API key at all since it's ours. Per CLAUDE.md, use `<THEHIVE_API_KEY>`
  as a placeholder in anything you show me or commit — real values only ever go
  into Shuffle's secrets store or the VM's environment.
- **Where Cortex fits alongside this**: Cortex responders remain the mechanism for
  anything that needs to *act* on infrastructure (block IP, isolate host) — Shuffle
  can also call Cortex's API directly as just another HTTP node, so the same
  workflow engine ends up orchestrating both "call the local LLM" and "run a
  Cortex responder" steps, which is exactly the unification you're after.

### 6.4 — Example prompt template (starting point, not final)

```
You are assisting a SOC analyst with initial triage of a security alert.
Given the alert metadata and the raw underlying event below, respond with ONLY
a JSON object with these exact keys: summary, severity (low/medium/high/critical),
mitre_technique (ID and name), recommendation.

Alert metadata:
{case_title}, {case_description}, {source_ip}, {dest_ip}, {timestamp}

Raw event:
{raw_event_json}

Be concise. The summary should be 1-2 sentences a non-specialist could
understand. The recommendation should be one concrete next action, not a
generic list.
```

- Test this against real cases from Task 1/2/5's attacks once you have them —
  don't design the prompt against synthetic examples, use actual alert data from
  your own SOC so the field names and event shapes match reality.

### 6.5 — Build order (do these in sequence, validate each before moving on)

1. **Install Ollama and pull a model first, no workflow yet**: `ollama pull
   llama3.1:8b`, then test one real TheHive case (e.g. the Juice Shop SQLi-bypass
   alert) and its raw event with a plain `curl` call against
   `http://localhost:11434/api/generate` by hand — see if the output is actually
   useful before building anything around it.
2. **Stand up Shuffle** (`docker compose up`), log in, create one organization,
   add the TheHive API key to its variable store. Confirm you can reach both
   Shuffle and Ollama in a browser/`curl` over Tailscale from wherever Shuffle
   runs.
3. **Build the workflow with a manual "Change Me" trigger first, not a webhook** —
   Shuffle lets you run a workflow on-demand with sample input. Wire up the HTTP
   nodes (fetch case → fetch raw event → call Ollama → post comment) and run it
   manually against one real case ID. Use Shuffle's execution log to debug each
   node's actual input/output — this is much easier than debugging a script with
   print statements.
4. **Verify the comment lands correctly in the TheHive UI**, formatted and clearly
   labeled as AI-generated.
5. **Swap the manual trigger for a webhook** — configure TheHive to call
   Shuffle's webhook URL on new-case-create (or use Shuffle's own polling trigger
   node against TheHive's API if TheHive's outgoing webhook support turns out to
   be awkward to configure — Shuffle supports both, pick whichever gets you a
   reliable trigger fastest).
6. **Expand automated response beyond block-an-IP** — once the AI-triage workflow
   is working, add 1-2 more workflows using the same Shuffle pattern (e.g.
   auto-disable a compromised Windows account via a Cortex responder node,
   auto-enrich a case with an IP reputation HTTP call before the AI node even runs
   — better AI output from richer input). Each new automation is a new workflow
   in the same Shuffle instance, reusing the same trigger/secrets setup.

### 6.6 — What "done" looks like for this task

One real alert (pick the strongest story — the SQLi full-account-takeover is a
good candidate) goes: attack happens → Suricata/app-log detects it → TheHive case
created → AI triage comment appears on the case within ~30 seconds → you show
this live to the encadrant. That single clean demo is worth more than several
partially-working features.

---

## Task 7 — Consolidate and prepare the final demo

- Build one master "SOC Overview" dashboard tying together all sources (Suricata
  WAN/DMZ/LAN, Juice Shop, Linux host, Windows host).
- Finalize the MITRE use-case catalog, the attack-chain writeups, and the AI-triage
  demo into the report.
- Full dry-run of the live demo end-to-end (same spirit as
  `demo/attack-scenarios.md` — copy-paste commands, no improvisation on the day).
- Leave real buffer time before the final presentation — every phase of this
  project so far has hit at least one real, time-consuming surprise (pfSense
  outages, log pipeline breaks, stale config). Don't schedule the demo dry-run for
  the same day as the deadline.

---

## Running principles (carried over from what's worked so far)

- Document negative results, not just successes (path traversal that didn't work
  was worth keeping — same standard applies going forward).
- Prefer application-layer/relay fixes over firewall rule changes on pfSense unless
  necessary — pf/Tailscale interactions have caused real outages twice this project.
- Verify with live evidence at every step (screenshot + underlying data), not just
  "should be working."
- For the AI-triage work specifically: validate the prompt against real data before
  automating, and keep AI output clearly labeled and separate from anything that
  auto-executes.
