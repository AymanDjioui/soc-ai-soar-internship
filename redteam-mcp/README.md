# Red-Team MCP Server

A custom [Model Context Protocol](https://modelcontextprotocol.io) **server** that lets
Claude Code (the MCP *client*) drive a Kali Linux attacker box to validate the blue-team
SOC detection/response pipeline. Built for this internship — inspired by public
pentest-MCP projects but written from scratch so it maps 1:1 onto our own detection
rules and enforces our own lab-scope guardrail.

## Architecture

```
Claude Code (MCP client, already running)
  └── redteam-mcp/server.py  (this MCP server, runs locally as a stdio process)
        └── SSH ──► Kali VM (100.125.163.9, on the Tailscale mesh)
                      └── runs nmap / sqlmap / impacket / netexec / msfvenom / ...
                            └── attacks lab victims (Juice Shop, Windows, Linux)
```

The server exposes each offensive tool as an MCP tool. When called, it SSHes into Kali,
runs the real utility against a lab target, and returns the output.

## Safety: the scope guard (mirrors the SOAR `policy_guard`)

Every tool validates its target through `_assert_in_scope()` before running. This is the
red-team analogue of the blue-team orchestrator's containment guard:

- **Allowed:** lab LAN `192.168.10.0/24`, lab DMZ `172.16.0.0/24`, local VMware segment
  `192.168.116.0/24`, and the three lab-victim Tailscale IPs.
- **Explicitly refused:** the SOC's own infrastructure (ELK, TheHive/Cortex, the GPU LLM
  host, Kali itself) — defensive assets are never attack targets, exactly as they are
  *protected assets* on the SOAR side.
- **Refused by default:** the entire public internet. This tool cannot attack anything
  outside the lab.

## The 16 tools

| Tool | Wraps | Maps to detection rule |
|---|---|---|
| `nmap_scan` | nmap | pfsense_portscan (T1046) |
| `run_sqlmap` | sqlmap | juiceshop_sqli (OWASP A03) |
| `run_hydra` | hydra | juiceshop_bruteforce / *_ssh_bruteforce (T1110) |
| `http_request` | curl | generic escape hatch — precise one-shot payloads/JSON APIs |
| `http_json_bruteforce` | curl (loop) | juiceshop_bruteforce / *_login_bruteforce (T1110) — JSON APIs hydra's http-post-form can't handle cleanly |
| `run_nikto` | nikto | web-attack recon |
| `run_gobuster` | gobuster | content discovery |
| `netexec_enum` | netexec/nxc | Windows enumeration |
| `smb_enum` | enum4linux | Windows recon |
| `dump_secrets` | impacket-secretsdump | win_credential_dump (T1003.001) |
| `wmi_exec` | impacket-wmiexec | win_wmi_execution (T1047) |
| `psexec` | impacket-psexec | win_new_service |
| `winrm_exec` | netexec winrm | win_lateral_movement (T1021) |
| `ssh_exec` | ssh | linux_root_login (T1078) |
| `linpeas_scan` | linpeas.sh | *(no rule — documents a real coverage gap)* |
| `msf_generate_payload` | msfvenom | win_defender_disabled, pfsense_outbound_anomaly/dns_tunnel |

## Config (env vars, lab defaults baked in)

| Var | Default |
|---|---|
| `KALI_HOST` | `100.125.163.9` |
| `KALI_USER` | `kali` |
| `KALI_PASS` | `kali` |
| `REDTEAM_TIMEOUT` | `300` (seconds/tool) |
| `REDTEAM_MAX_OUTPUT` | `20000` (chars returned) |

## Activation

Registered via the project-root `.mcp.json`. Claude Code loads it on start; a newly
added server needs a one-time approval / session reload before its tools appear. Until
then (or for scripted use) the exact same tools can be driven directly:

```bash
python3 -c "import sys; sys.path.insert(0,'redteam-mcp'); import server; \
  print(server.nmap_scan('192.168.10.20'))"
```

## Requirements

- The `mcp` Python SDK (`pip install -r requirements.txt`)
- `sshpass` + `ssh` on the host running the server
- Kali reachable over SSH (Tailscale), with the offensive tools installed (stock Kali)

## Burp Suite MCP server (separate, in `.mcp.json` as `burp`)

The official PortSwigger extension (https://github.com/PortSwigger/mcp-server),
running inside a real Burp Suite Community Edition instance on Kali. Exposes
Burp's own tools (`send_http1_request`, `send_http2_request`, `create_repeater_tab`,
`send_to_intruder`, `url_encode`/`decode`, `base64_encode`/`decode`, etc.) — the
precise, raw-HTTP-crafting complement to this server's CLI-tool wrappers. Built
specifically to handle JSON-API login testing (Juice Shop-style) that `hydra`'s
`http-post-form` module can't parse cleanly (see PROJECT-STATE.md, 2026-08-18).

**Must run on a real desktop, not headless Xvfb** — confirmed by direct testing:
under Xvfb the extension's own Ktor server silently failed to bind (no error
anywhere, even at Debug log level) and several core Burp tabs (Target, Extensions)
failed to render (`Error initializing Target tool`). On Kali's real VM console
(VMware, not SSH+Xvfb+VNC) it started correctly on the very first try. Currently
running via Kali's VMware console session, `Temporary project in memory` (Community
Edition doesn't support project files on disk), MCP server bound to `127.0.0.1:9876`
on Kali, with the 3 lab targets (`100.70.145.65:8080`, `100.101.109.12`,
`100.105.72.46`) added to Burp's own Auto-Approved HTTP Targets list (bypasses the
per-request manual-approval popup for known-safe lab traffic; anything else still
requires a human click in the Burp UI — a real safety feature, not a limitation to
work around).

**Connectivity, from Claude Code's side (runs on the laptop, not Kali or the ELK/GPU
VMs)**: Burp's MCP server only binds to `127.0.0.1` on Kali (Community Edition has no
option to bind elsewhere in this build), so it isn't reachable directly over
Tailscale. Bridged with an SSH port-forward instead of exposing the port:
```bash
ssh -N -L 9876:127.0.0.1:9876 kali@100.125.163.9
```
This must be running (kept open, e.g. in `nohup`/a background terminal) whenever the
`burp` MCP tools are used. `.mcp.json`'s `burp` entry runs the extension's own bundled
stdio↔SSE proxy (`redteam-mcp/burp-proxy/mcp-proxy-all.jar`, copied locally from
Kali's `~/burp-mcp-server/libs/`) pointed at `http://localhost:9876` — confirmed
working via a direct manual test (connected, listed all 9+ tools) before wiring it
into `.mcp.json`.

**Known fragility**: both the Kali-side Burp process and the local SSH tunnel are
manually-started, not services — if either dies (VM reboot, laptop sleep, tunnel
drop), the `burp` MCP tools stop working silently until both are restarted by hand.
Not automated yet; worth a systemd unit / auto-reconnect wrapper if this proves
worth keeping long-term.
