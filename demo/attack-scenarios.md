# Live Demo Runbook — Attack Scenarios

Copy-paste these commands into your terminal one at a time during a live demo, then
show the corresponding result in Kibana. All commands target the real detection path
(`100.70.145.65:8080`, the Tailscale → pfSense NAT → DMZ path that Suricata actually
monitors) — **do not** run these against `100.78.58.45` or `172.16.0.10` directly,
that bypasses Suricata entirely and won't show up anywhere.

Run from your own laptop (djioui), already on the tailnet. No SSH needed except for
scenario 4.

---

## 1. Port / service scan

```bash
nmap -sV -sC -p 8080 100.70.145.65
```

**What to show in Kibana**: `suricata-alerts-*` index (or the Suricata dashboard) —
filter for signature containing "Nmap" or "Scripting Engine". Alert should appear
within a few seconds of the scan running.

---

## 2. XSS (cross-site scripting)

```bash
curl "http://100.70.145.65:8080/rest/products/search?q=<script>alert(1)</script>"
```

**What to show**:
- `suricata-alerts-*` — SID 2009714 (ET WEB_SERVER Possible XSS)
- Dashboard **"Juice Shop - Traffic & Security Overview"** → *Suspicious Request Events*
  panel — the raw event with the `<script>` payload should appear

---

## 3. SQL injection

Quick single-shot version (fast, good for a live demo — full `sqlmap` run takes
several minutes and isn't ideal to sit through live):

```bash
curl "http://100.70.145.65:8080/rest/products/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--"
```

Full `sqlmap` run (use if you have time / want the richer multi-signature result from
the original test):

```bash
sqlmap -u "http://100.70.145.65:8080/rest/products/search?q=test" --batch --level=2 --risk=1
```

**Note**: sqlmap's heavy time-based blind queries can briefly degrade the Juice Shop
app (seen before — a real, citable finding about SQLite fragility under blind SQLi
timing attacks, not a bug in the pipeline). If the app returns 502s right after, give
it 10-20 seconds to recover before the next scenario.

**What to show**: `suricata-alerts-*` — multiple distinct signatures from one run
(UNION SELECT, SQL injection detection, etc.). Dashboard's *Error Responses Over Time*
panel should also show a spike if the query caused a 500/502.

---

## 4. Known-bad-traffic baseline

**Must be run from pfSense's own shell**, not your laptop — `testmyids.com` is a
public domain reached over your own internet connection, which never touches
pfSense's WAN if run from your laptop directly (a real gap found and understood
earlier in this project, not a detection failure).

```bash
ssh admin@100.70.145.65
curl http://testmyids.com
```

**What to show**: `suricata-alerts-*` — SID 2100498, GeoIP map panel if available
(shows the source as Germany, where testmyids.com is hosted).

---

## 5. Juice Shop app-layer traffic (bonus — shows the app dashboard specifically)

```bash
curl "http://100.70.145.65:8080/rest/products/search?q=SOMETHING"
```

**What to show**: dashboard **"Juice Shop - Traffic & Security Overview"** —
*Requests Over Time* ticks up, *Top Request URIs* shows the new query, *Top User
Agents* shows `curl` if run directly (a legitimate "this isn't a normal browser"
signal worth pointing out live).

---

## Quick reference — where everything lives in Kibana

| What | Where |
|---|---|
| Raw Suricata alerts | Discover → `suricata-alerts-*` |
| Raw Juice Shop HTTP logs | Discover → `juiceshop` data view (`juiceshop-docker-*`) |
| Juice Shop dashboard | Dashboards → "Juice Shop - Traffic & Security Overview" |
| IDS/Suricata dashboard | Dashboards → IDS Detections (existing, from earlier session) |

Screenshots from the most recent live run of all 5 scenarios: `demo/screenshots-2026-07-20/`
