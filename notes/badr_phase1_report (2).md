# Project Report: Machine 2 Phase 1 Contributions (Badr)

## 1. Overview
As part of the Devoteam internship project "SOAR and AI for detection improvement in the SOC," my responsibility (Machine 2) focuses on the core response, orchestration, and boundary security components. While Machine 1 (Ayman) handles the ELK (SIEM) log collection, my infrastructure focuses on the containment and case-management stack.

My assigned stack includes:
* **PfSense (VM):** Acting as the primary lab firewall, generating network traffic logs to be forwarded to Logstash, and serving as the prospective target for active containment auto-blocks.
* **TheHive:** Acting as the Security Incident Response Platform (SIRP) responsible for managing alerts escalated by ELK.
* **Cortex:** Acting as the automation layer executing analysis and orchestration jobs against observables (IoCs).

## 2. Infrastructure Setup & Architecture
Due to local computing constraints (12GB RAM on Arch Linux, shared with a PfSense VM running under VMware), the decision was made to split the infrastructure using the cloud:
* **PfSense** was deployed locally as a Virtual Machine on VMware on Arch Linux, using NAT networking so it could obtain local network connectivity alongside Machine 1.
* **TheHive & Cortex** (along with backend dependencies Elasticsearch, Cassandra, and Nginx reverse proxies) were deployed via Docker Compose on an **AWS EC2 instance** (Ubuntu 26.04, `eu-north-1` Stockholm region, 7.6GB RAM).

This decoupled architecture mitigated local hardware bottlenecks while simulating a realistic distributed SOC environment.

## 3. Implementation and Configuration

### 3.1. PfSense Deployment
* Successfully installed and configured a PfSense virtual machine as the edge device for the lab network.
* Configured PfSense as a VMware virtual machine using NAT networking. With NAT the VM has outbound network access through the host but is not directly reachable from other physical LAN hosts unless port-forwarding or a VPN is used. PfSense forwards firewall logs outbound to Machine 1 (ELK). To enable cloud-based TheHive/Cortex to reach the local PfSense for auto-blocking, we installed Tailscale on all devices — including the PfSense VM — establishing a Tailscale mesh VPN for secure connectivity.
* Enabled detailed logging for firewall events to feed the upcoming SIEM pipeline (Phase 1 completion requires verifying these logs reach Elasticsearch on Machine 1).

### 3.2. Docker Environment Setup
* Deployed the complete **7-container Docker stack** on AWS:
  * `thehive` (strangebee/thehive:5.7.1)
  * `cortex` (thehiveproject/cortex:4.0.1)
  * `elasticsearch` (elasticsearch:8.19.15) — TheHive backend
  * `elasticsearch-cortex` (elasticsearch:8.19.15) — Cortex backend
  * `cassandra` (cassandra:4.1.11) — TheHive database
  * `nginx` (nginx:1.31.1) — TheHive reverse proxy (port 443)
  * `nginx-cortex` (nginx:1.31.1) — Cortex reverse proxy (port 4443)
* Fixed Docker group permissions: the `ubuntu` user was not in the `docker` group, requiring `sudo` for every command. Resolved with `sudo usermod -aG docker ubuntu`.

### 3.3. Cortex Initial Setup
* Completed the **first-time Cortex setup wizard**, creating the admin account and the `devoteam-soc` organization.
* Generated an **API key** from the Cortex organization for use by TheHive's connector.

### 3.4. TheHive ↔ Cortex Integration
* Configured the **TheHive Cortex connector** under Organization settings, using the generated API key to authenticate.
* Verified bidirectional communication: TheHive can dispatch analysis jobs to Cortex, and Cortex returns enrichment reports back to TheHive case observables.

### 3.5. Cortex Analyzers Configuration
Enabled foundational SOC Analyzers to automate Threat Intelligence gathering. The combination was chosen to implement a **Tier 1 Triage Automation** strategy, ensuring that every observable is enriched across multiple intelligence vectors (Network, Payload, and Threat Actor) before a human analyst reviews the case:
* **VirusTotal** — Aggregates 70+ antivirus engines. Chosen as the baseline check for files, hashes, IPs, and URLs. Provides an immediate verdict on known malware.
* **AbuseIPDB** — Crowdsourced network threat scoring. Chosen specifically because our primary log source is a **PfSense firewall**, meaning most alerts involve IP addresses. AbuseIPDB tells us *why* an IP is malicious (e.g., "reported 50 times for SSH brute-forcing"), which VirusTotal alone does not provide.
* **AlienVault OTX** — Threat Intelligence platform. Chosen to connect isolated indicators (a single IP) to larger attack campaigns and known Threat Actors (e.g., APT groups). This upgrades the SOC from "reacting to indicators" to "understanding the adversary."
* **URLhaus** — Dedicated malware URL tracker. Chosen because a majority of initial compromises happen via malicious links (phishing, drive-by downloads). URLhaus is faster and more precise for URL-specific analysis than generic scanners.

### 3.6. End-to-End Testing
* Created **Case #1** ("Test case - Cortex integration") within TheHive.
* Added the observable `8.8.8.8` (IP address) to the case.
* Successfully triggered automated VirusTotal reputation scans through Cortex, verifying the full pipeline from case creation → observable enrichment → report retrieval.

## 4. Technical Challenges & Resolutions
During deployment, several technical hurdles were encountered and resolved:

### 4.1. JVM Heap Misconfiguration (`Xms > Xmx`)
* **The Problem:** TheHive's JVM was configured with `-Xms3000M` (minimum heap = 3GB) and `-Xmx1500m` (maximum heap = 1.5GB). This is an invalid Java configuration where the minimum exceeds the maximum, causing immediate startup failure.
* **The Solution:** Corrected the mismatch using `sed` to align both values at 1500m.

### 4.2. JVM Resource Starvation and OOM Kills
* **The Problem:** After fixing the Xms/Xmx mismatch, TheHive still periodically crashed during startup. System logs (`dmesg`) revealed the Linux Kernel was terminating the Java process via the Out-Of-Memory (OOM) killer. The JVM heap size (`-Xms1500m -Xmx1500m`) consumed the entirety of the Docker container's 1.5GB memory limit, starving the OS and Metaspace overhead.
* **The Solution:** The container memory limit was increased to `2GB`. The JVM was explicitly re-tuned to a 1024MB heap, while reserving 400MB for `MaxMetaspaceSize` and `ReservedCodeCacheSize`.

### 4.3. Container Initialization and Health-check Timeouts
* **The Problem:** Despite booting successfully, the Docker daemon frequently flagged TheHive and Cortex as `unhealthy`. The default Docker Healthcheck `start_period` (40 seconds) was too short for the EC2 instance's I/O speeds to initialize Java actors and databases.
* **The Solution:** The `docker-compose.yml` was customized to extend the healthcheck `start_period` to 90 seconds and the timeout to 5 seconds. Cortex's health-check URL path (`/cortex/api/status`) was also corrected to the actual endpoint `/api/status`.

### 4.4. Docker Compose `${PWD}` Variable Warning
* **The Problem:** Docker Compose was printing `WARN: The "PWD" variable is not set. Defaulting to a blank string.` when starting the Cortex stack. The `.env` file used `${PWD}` to set the `cortex_docker_job_directory`, which depends on the working directory at launch time and is unreliable across different shell sessions.
* **The Solution:** Verified that the variable resolved correctly inside the running container using `docker exec printenv`. Documented as a potential risk and recommended hardcoding the absolute path for production reliability.

### 4.5. Cortex Analyzer Job Failures (AccessDeniedException)
* **The Problem:** When executing an analyzer in Cortex, the jobs queued but immediately failed with `java.nio.file.AccessDeniedException` targeting `/tmp/cortex-jobs/`. The `cortex-jobs` directory on the host had been empty since creation — no analyzer job folders were ever written despite Cortex generating job IDs. The spawned Docker analyzer workers lacked permission to read/write to the job directories.
* **The Solution:** Applied permissive ACLs (`chmod -R 777`) to the `cortex-jobs` volume, universally allowing the transient Docker workers to create and return their threat reports to TheHive seamlessly. Restarted the Cortex container to apply the fix.

### 4.6. TheHive-to-Cortex Connector Protocol Mismatch
* **The Problem:** After deploying both applications, TheHive failed to communicate with Cortex. Running `curl -v https://cortex:9001/api/status` from inside TheHive's container generated an `OpenSSL wrong version number` error, indicating a TLS handshake failure. Cortex does not encrypt traffic on its internal application port (9001); HTTPS is strictly handled by the `nginx-cortex` reverse proxy externally.
* **The Solution:** Edited TheHive's `application.conf` to target the plain HTTP endpoint (`url = "http://cortex:9001"`) over the internal Docker bridge network, perfectly resolving the integration failure.

### 4.7. Docker Group Permissions
* **The Problem:** The `ubuntu` user on the EC2 instance was not a member of the `docker` group, meaning every Docker command required `sudo`.
* **The Solution:** Added the user to the Docker group with `sudo usermod -aG docker ubuntu && newgrp docker`.

## 5. Phase 3: Active Defense & Auto-Block Responder Automation
As part of the final phase of the SOAR automation roadmap, I developed a custom Cortex Responder capable of dynamically blocking malicious IP addresses on the local PfSense firewall directly from the cloud-based TheHive interface.

### 5.1. Architecture & Network Bridging
Because the Cortex/TheHive infrastructure resides in AWS and the PfSense firewall sits on the local LAN, direct communication was blocked by NAT.
* **Tailscale VPN:** Deployed Tailscale across all instances, establishing a secure Mesh VPN.
* **Flask Webhook Listener:** Deployed a persistent Python Flask application on the AWS Host (running as a `systemd` service) that listens for POST requests from the Cortex Responder and executes an SSH command over the Tailscale backend directly to the PfSense VM.
* **PfSense EasyRule:** Authenticated SSH sessions trigger the `easyrule block wan <ip>` command to instantly update the firewall's alias tables.

### 5.2. Custom Cortex Bash Responder
The native logic required overriding Cortex defaults to reliably proxy the observable data:
* Developed `PfSense_Blocker`, mapped directly into Cortex's `/opt/cortexneurons/responders/` directory.

#### Technical Hurdles Resolved During Implementation:
* **HOCON Array Syntax Error:** The local responder path inside Cortex's `application.conf` was initially provided as a URL instead of a `path = []` array, preventing initialization.
* **TheHive Observable Data Types:** TheHive 5.x passes indicators as `case_artifact` rather than standalone `ip` datatypes. Fixed the responder's `PfSenseBlocker.json` config mapping to ensure it was strictly bound to `"thehive:case_artifact"`.
* **Alpine Linux Binary Scarcity:** Attempted to write the responder in Python, but the Cortex responder Docker execution environment lacked the `python3` binary. Re-engineered the script completely into an Alpine-compatible Bash script natively leveraging standard `curl`, `awk`, and `grep`.
* **Cortex Job Directory Parameter Injection:** Discovered that Cortex does not pass JSON payloads to custom scripts via standard input (`stdin`) as initially expected, nor as a raw string argument. Cortex dynamically creates a transient folder structure globally mapped at `$1/input/`, dropping physical payload files there. Updated the bash script to dynamically parse `$1/input/*`.
* **Strict JSON Output Validation (`operations` Array):** The script successfully triggered the block but initially generated a "Failure" badge in Cortex. Examination of the `cortexutils` core library revealed a hidden schema requirement: Cortex exclusively reports success if the output physically writes to `$1/output/output.json` and perfectly matches the `{ "success": true, "operations": [] }` schema. Modifying the output format yielded comprehensive success.

## 6. Literature Review & Benchmark Analysis (Phase 2)
To justify the architectural choices made in Phase 1 and 3, a comparative analysis of the current market state for SOAR (Security Orchestration, Automation, and Response) and AI-driven detection mechanisms was conducted. The goal was to identify solutions that provide maximum compatibility with the ELK stack while balancing deployment complexity and open-source licensing constraints.

### 6.1. SOAR Engine Benchmark

The following table evaluates various SOAR and automation orchestration platforms based on criteria critical to a modern, open-source SOC ecosystem.

| Feature / Platform | TheHive + Cortex | Shuffle | Apache StackStorm (ST2) | n8n | Splunk SOAR (Phantom) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Licensing** | Open Source (AGPL) | Open Source (MIT) | Open Source (Apache 2) | Fair-code / Proprietary | Commercial / Proprietary |
| **ELK Integration** | Native (via Webhooks) | Strong (API/Webhooks) | Strong (Packs) | Moderate | Native |
| **Primary Use Case** | Case Management & Incident Response | General SOC Orchestration | IT Ops & Event-Driven Auto | General Workflow Auto | Enterprise Security Auto |
| **Learning Curve** | Moderate | Low (Visual Builder) | High (YAML/Python driven) | Low (No-Code GUI) | High (Proprietary config) |
| **Community Support**| Very High (SecOps specific) | Growing rapidly | High (DevOps focus) | Very High (Broad focus) | Enterprise Support |
| **Python Expandability**| High (Native Python CortexUtils) | High (App Creator) | High (Python Actions) | Moderate (JS focused) | High |

**Conclusion & Justification:**
While *Shuffle* and *n8n* offer highly accessible visual workflow builders, they act as general automation platforms. *TheHive alongside Cortex* was selected for this lab because they collectively form a dedicated Security Incident Response Platform (SIRP). The seamless coupling of TheHive's case management with Cortex's parallel analyzer execution engine provides a uniquely focused threat intelligence capability that general-purpose workflows cannot match out-of-the-box. Furthermore, Cortex's ability to host custom Python and Bash responders (as demonstrated in Phase 3) provided the exact programmatic flexibility necessary to tunnel into our isolated PfSense environment.

### 6.2. AI & ML Detection Solutions Benchmark

Augmenting traditional rule-based SIEMs (like ELK) with Artificial Intelligence reduces false positives and accelerates threat hunting. The following evaluates the leading paradigms for integrating AI into a SOC.

| Feature / AI Paradigm | Elastic Machine Learning | Wazuh AI Integration (LLMs) | Custom LLM SecOps Agents |
| :--- | :--- | :--- | :--- |
| **Core Mechanism** | Unsupervised ML algorithms detecting anomalies in time-series data. | Integration with generative AI APIs (e.g., ChatGPT, Claude) for alert summarization. | Agentic frameworks querying internal databases and reasoning through playbooks. |
| **Primary Benefit** | Identifying Unknown Threats (0-days, anomalous data spikes). | Alert context and human-readable incident summaries. | Autonomous triage and initial incident response execution. |
| **Infrastructure Req.** | High (Requires Elastic Platinum/Enterprise license or heavy resource consumption). | Low (Acts as an API passthrough to external LLMs). | Moderate (Requires hosting local models or API access, plus agent orchestration). |
| **False Positive Rate**| Moderate to High (Requires significant tuning periods). | Low (Summarizes existing alerts; does not generate new ones). | Varies depending on Model prompt engineering. |

**Conclusion & Justification:**
The current trajectory of SOC automation points heavily toward combining **LLM SecOps Agents** with orchestrated runbooks. While Elastic ML excels at identifying quantitative anomalies (e.g., a sudden spike in DNS traffic), LLM integrations (such as prompting an LLM to analyze the context of a Cortex VirusTotal report) provide qualitative analysis. For future project phases or enterprise implementation, deploying an open-source LLM (e.g., Llama 3) as a Cortex Analyzer would bridge the gap between AI-driven theoretical analysis and immediate SOAR implementation.

## 7. Phase 4: Network Architecture Redesign & DMZ Deployment

### 7.1. Architecture Diagram

The following diagram illustrates the complete SOC lab architecture, including the SOAR closed-loop pipeline, the WAN/LAN/DMZ segmentation, and the red "Auto-Block" return path.

![SOC Architecture Diagram](socsoar.drawio.png)

**Project Title:** *"Architecture: SOAR and AI (AI pending) for detection improvement in the SOC"*

### 7.2. Network Segmentation Design

The lab network was redesigned from a flat NAT topology into a properly segmented enterprise-grade architecture using PfSense as the central routing and firewall appliance. Three distinct network zones were established within VMware Workstation:

| Zone | VMnet | Subnet | PfSense Interface IP | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **WAN** | VMnet8 (NAT) | DHCP from VMware | `192.168.84.134` (DHCP) | Internet access for PfSense |
| **LAN** | VMnet2 | `192.168.10.0/24` | `192.168.10.2` | Internal endpoints (Windows 10, Ubuntu Desktop) |
| **DMZ** | VMnet1 | `172.16.0.0/24` | `172.16.0.2` | Isolated vulnerable application zone |

**Design Rationale:** The DMZ is architecturally isolated from the LAN, ensuring that a compromise of the vulnerable application cannot pivot directly into the internal network. All traffic between zones is mediated exclusively by PfSense firewall rules, mirroring real-world enterprise network design.

### 7.3. PfSense Outbound NAT for DMZ Internet Access

The DMZ zone initially had no internet connectivity. Devices on `172.16.0.0/24` could not resolve DNS or download packages, which was critical for Docker image pulls.

* **Problem:** PfSense's default Automatic Outbound NAT only generated masquerade rules for the LAN interface. The DMZ subnet (`172.16.0.0/24`) was not included, meaning all outbound traffic from the DMZ was silently dropped at the WAN boundary.
* **Solution:** Switched PfSense from **Automatic Outbound NAT** to **Hybrid Outbound NAT** mode under `Firewall → NAT → Outbound`. Created a manual outbound NAT rule:
  * **Interface:** WAN
  * **Source:** `172.16.0.0/24` (DMZ net)
  * **Translation:** Interface Address (WAN IP)
  This allowed the DMZ to masquerade behind the PfSense WAN IP and reach the internet for package downloads.

### 7.4. DMZ Target VM: Alpine Linux Deployment

An Alpine Linux virtual machine was deployed in the DMZ to host the vulnerable web application. The deployment required resolving multiple technical challenges.

#### 7.4.1. VMware SCSI Hard Disk Boot Failure
* **Problem:** Alpine Linux's `setup-alpine` installer completed successfully, but the VM failed to boot from the hard disk after removing the ISO. The error displayed was `"Operating System not found"`. The root cause was that Alpine's `syslinux` bootloader is incompatible with VMware's default SCSI virtual disk controller.
* **Solution:** Removed the SCSI hard disk from the VM settings and re-created it as a **SATA** virtual disk (8 GB). Re-ran `setup-alpine` with the new SATA drive, which allowed the bootloader to install correctly.

#### 7.4.2. DNS Resolution Failure (APK Mirror Unreachable)
* **Problem:** During `setup-alpine`, the APK Mirror step failed with `wget: bad address 'mirrors.alpinelinux.org'`. The `ping 8.8.8.8` command succeeded (proving IP routing worked), but `ping google.com` failed, confirming DNS was not configured.
* **Solution:** Manually injected a DNS resolver before running the installer:
  ```sh
  echo "nameserver 8.8.8.8" > /etc/resolv.conf
  ```
  This allowed the installer to resolve `dl-cdn.alpinelinux.org` and download the `syslinux` bootloader package, completing the installation successfully.

#### 7.4.3. 32-bit Architecture Incompatibility
* **Problem:** After completing the Alpine installation and deploying Docker, the `docker run` command for Juice Shop failed with: `no matching manifest for linux/386 in the manifest list entries`. The Alpine ISO used was the `x86` (32-bit) variant, and the Juice Shop Docker image only publishes `linux/amd64` and `linux/arm64` manifests.
* **Solution:** Deleted the 32-bit VM entirely. Downloaded the correct **Alpine Linux Standard x86_64 ISO** and rebuilt the VM from scratch. The entire rebuild (VM creation → `setup-alpine` → SSH access) took approximately 13 minutes, leveraging the knowledge gained from prior installation attempts.

### 7.5. Docker & OWASP Juice Shop Deployment

With the 64-bit Alpine VM permanently installed and booted from the SATA hard disk, Docker and the vulnerable application were deployed.

#### 7.5.1. Docker cgroups Dependency
* **Problem:** Docker installed successfully via `apk add docker`, and `rc-service docker start` reported `[ ok ]`. However, running any `docker` command returned: `failed to connect to the docker API at unix:///var/run/docker.sock: no such file or directory`. Inspecting `/var/log/docker.log` revealed: `Daemon shutdown complete: failed to start daemon: Devices cgroup isn't mounted`.
* **Solution:** Alpine Linux does not mount cgroups by default. The fix was:
  ```sh
  rc-update add cgroups boot
  rc-service cgroups start
  rc-service docker restart
  ```

#### 7.5.2. TLS Handshake Timeout on Docker Pull
* **Problem:** `docker run bkimminich/juice-shop` failed with `TLS handshake timeout` when attempting to pull the image from Docker Hub. The virtual network path (Alpine VM → PfSense → VMware NAT → Host) introduced packet fragmentation issues.
* **Solution:** Reduced the network MTU and disabled IPv6 to eliminate TLS negotiation failures:
  ```sh
  ip link set dev eth0 mtu 1400
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  rc-service docker restart
  ```
  The Juice Shop image then downloaded successfully.

#### 7.5.3. Final Deployment Commands
The complete deployment sequence for the DMZ Juice Shop application:
```sh
# Network configuration
echo "nameserver 8.8.8.8" > /etc/resolv.conf
sed -i '/community/s/^#//' /etc/apk/repositories

# Package installation
apk update
apk add docker

# Service initialization (cgroups required for Docker on Alpine)
rc-update add cgroups boot
rc-update add docker boot
rc-service cgroups start
rc-service docker start

# MTU fix for VMware virtual networking
ip link set dev eth0 mtu 1400
sysctl -w net.ipv6.conf.all.disable_ipv6=1

# Deploy vulnerable application
docker run -d -p 80:3000 bkimminich/juice-shop
```

The application became accessible at `http://172.16.0.10` from any machine on the LAN or DMZ segments, displaying the OWASP Juice Shop storefront.

### 7.6. PfSense NAT Port Forwarding (External Attack Surface)

To enable the simulated attacker (Ayman) to reach the Juice Shop from outside the local network via the Tailscale VPN mesh, a NAT Port Forward rule was configured on PfSense.

#### 7.6.1. Port Conflict Resolution
* **Problem:** PfSense's own WebGUI was already listening on port 80 (HTTP) on the WAN interface. Forwarding port 80 to the DMZ would conflict with the management interface.
* **Solution:** Used port **8080** as the external-facing port, with PfSense translating it internally to port 80 on the Juice Shop VM.

#### 7.6.2. Interface Selection for Tailscale Traffic
* **Problem:** The initial Port Forward rule was configured on the **WAN** interface with a destination of **WAN Address**. However, Ayman's attacks arrive via the **Tailscale** VPN tunnel, which PfSense treats as a separate interface. Traffic entering the Tailscale interface never matched the WAN-bound Port Forward rule, resulting in connection timeouts.
* **Solution:** Edited the Port Forward rule to use:
  * **Interface:** `Tailscale`
  * **Destination:** `This Firewall (self)` (matches any PfSense-assigned IP, including the Tailscale address `100.70.145.65`)

#### 7.6.3. Final NAT Port Forward Rule

| Field | Value |
| :--- | :--- |
| **Interface** | Tailscale |
| **Protocol** | TCP |
| **Destination** | This Firewall (self) |
| **Dest. Port Range** | 8080 (Custom) |
| **Redirect Target IP** | `172.16.0.10` |
| **Redirect Target Port** | HTTP (80) |
| **Description** | NAT - Juice Shop DMZ Access |

**Verification:** Accessing `http://100.70.145.65:8080` from any device on the Tailscale mesh successfully loads the OWASP Juice Shop interface, confirming the complete attack path: `Attacker (Tailscale) → PfSense Port Forward → DMZ Juice Shop`.

### 7.7. Complete Attack Simulation Path

With all components deployed and verified, the end-to-end SOAR automated incident response pipeline is now operational:

1. **Attacker (Ayman)** launches attacks against `http://<PfSense-Tailscale-IP>:8080` from his machine via Tailscale.
2. **PfSense** forwards the traffic to the Juice Shop VM (`172.16.0.10:80`) in the DMZ and generates firewall logs.
3. **PfSense logs** are forwarded to **ELK (Machine 1 - Ayman)** via syslog for ingestion into Elasticsearch.
4. **ELK** processes the logs, applies detection rules, and escalates matching events as alerts to **TheHive** (AWS) via webhooks.
5. **TheHive** creates a case and extracts observables (attacker IP addresses).
6. **Cortex Analyzers** (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus) automatically enrich the observables with threat intelligence.
7. **Cortex Responder (PfSense_Blocker)** triggers the Flask webhook on AWS, which SSHs into PfSense over Tailscale and executes `easyrule block wan <attacker_ip>`.
8. **PfSense** immediately blocks all further traffic from the attacker's IP, completing the automated containment loop.

This closed-loop architecture demonstrates a fully functional **SOAR-driven automated incident response** capability, from initial attack detection through threat intelligence enrichment to active defense containment — all without manual analyst intervention.

## 7.8. Docker Log Forwarding: Juice Shop DMZ → PfSense Relay → SIEM

With the DMZ target VM and PfSense NAT rules in place, the final integration step was ensuring Juice Shop's Docker container logs reach the SIEM (Machine 1 - Ayman) for detection processing. Because the DMZ Juice Shop host has no Tailscale interface by design (isolating it from the mesh VPN per the segmentation rationale in 7.2), it cannot reach the SIEM's Tailscale address directly. PfSense — which has both a DMZ-facing leg (`172.16.0.2`) and a Tailscale leg (`100.70.145.65`) — was used as a two-hop relay.

```
Juice Shop (Docker host, DMZ, no Tailscale)
   --172.16.0.2:5517/tcp (local routing)-->
PfSense (syslog-ng relay)
   --100.99.54.59:5517/tcp (Tailscale)-->
SIEM (Logstash)
```

### 7.8.1. rsyslog Configuration on the Docker Host

`imfile` was used to tail Docker's container JSON logs and forward them as a raw payload to PfSense's DMZ interface:

```sh
cat > /etc/rsyslog.d/docker.conf << 'EOF'
module(load="imfile")

input(type="imfile"
      File="/var/lib/docker/containers/*/*-json.log"
      Tag="juiceshop-docker:"
      Severity="info"
      Facility="local0")

template(type="string" name="rawJSON" string="%msg%\n")

action(type="omfwd" target="172.16.0.2" port="5517" protocol="tcp" template="rawJSON")
EOF

service rsyslog restart
```

### 7.8.2. Syslog-ng Relay Installation on PfSense

PfSense's built-in syslog client (Status > System Logs > Settings > Remote Logging) only forwards pfSense's own generated logs — it cannot act as a relay for a third-party host's syslog traffic. The `syslog-ng` package was installed via **System > Package Manager** to provide this capability, configured with three objects under **Services > Syslog-ng > Advanced**:

* **Source** (`juiceshop_src`) — listens on the DMZ interface for incoming Docker logs:
  ```
  { network(ip("172.16.0.2") port(5517) transport("tcp") flags(no-parse)); };
  ```
  `flags(no-parse)` was required to prevent syslog-ng from interpreting the incoming line as an RFC3164/5424-formatted syslog message, which would otherwise mangle the raw JSON payload.

* **Destination** (`siem_dst`) — relays onward to the SIEM over Tailscale:
  ```
  { network("100.99.54.59" port(5517) transport("tcp")); };
  ```

* **Log** (`juiceshop_relay`) — links source to destination:
  ```
  source(juiceshop_src); destination(siem_dst);
  ```

A corresponding **Firewall > Rules > DMZ** rule was added permitting TCP port 5517 from the Juice Shop host to PfSense's DMZ interface.

### 7.8.3. Config Promotion Failure (`.tested` file never applied)

* **Problem:** All three syslog-ng objects saved without syntax errors, but **Status > Services** continued to show `syslog-ng` as stopped, and `/usr/local/etc/syslog-ng.conf` did not exist on disk. Investigation via SSH (noting PfSense's console shell is `tcsh`, not `bash` — standard `2>/dev/null` redirects behave differently) revealed that the GUI's syntax validator writes a verified config to `/usr/local/etc/syslog-ng.conf.tested`, but this build of the package never promoted that file to the live `syslog-ng.conf`, nor started the service from it.
* **Solution:** Confirmed the `.tested` file's contents matched the intended source/destination/log configuration, then manually promoted it and started the daemon:
  ```sh
  cp /usr/local/etc/syslog-ng.conf.tested /usr/local/etc/syslog-ng.conf
  /usr/local/sbin/syslog-ng -f /usr/local/etc/syslog-ng.conf
  ```
  The service was then restarted through **Status > Services** so it would run as a properly managed background process rather than the manual foreground instance.

### 7.8.4. Verification

Connectivity from the Juice Shop host to PfSense's relay listener was confirmed with:

```sh
nc -zv 172.16.0.2 5517
# 172.16.0.2 (172.16.0.2:5517) open
```

This completed the log path from the isolated DMZ container host through PfSense to the SIEM, enabling Juice Shop's application-layer activity — not just PfSense's firewall/filterlog events — to feed into Machine 1's detection pipeline described in Section 7.7.

## 8. Log Forwarding Complexity and Final Resolution: Direct VPN Deployment

### 8.1. The Subnet Routing Failure
The original plan for log forwarding from the internal LAN segments (specifically a Windows VM running Winlogbeat and an Alpine VM running syslog) to the SIEM was to avoid installing the Tailscale client on every endpoint. Instead, the strategy was to use PfSense as a Tailscale Subnet Router for the `192.168.10.0/24` network.

The following configurations were successfully validated:
* Advertised the `192.168.10.0/24` route on PfSense's Tailscale interface.
* Approved the route in the Tailscale admin console.
* Confirmed the SIEM (ELK host) accepted Tailscale routes using `--accept-routes` to route replies back to the subnet.
* Confirmed PfSense's firewall rules (LAN and Tailscale interfaces) were not blocking the traffic.
* Confirmed the SIEM's local firewall (`ufw`) was allowing traffic on port 5044 and Logstash was actively listening.

### 8.2. TCP Handshake Breakdown (Asymmetric Routing / State Drops)
Despite proper routing and firewall configurations, we hit a wall: the actual TCP handshake between the internal VMs (Windows) and the SIEM failed to complete. Packet capture analysis (`tcpdump`) on the SIEM proved that it received the initial `SYN` packet and instantly responded with a `SYN-ACK`. However, this reply never resulted in an established connection—the Windows VM either timed out or ultimately sent `RST` packets. 

Extensive troubleshooting was performed, including:
* Ruling out Windows Firewall.
* Modifying PfSense state policy and analyzing packet states.
* Testing sloppy-state configurations to mitigate potential asymmetric routing drops.

None of these resolved the dropped return traffic. The underlying issue appeared to be related to how PfSense handles stateful inspection across VPN interfaces, likely dropping the asymmetric return packets or failing to correctly associate the Tailscale tunnel traffic back with the original LAN sockets.

### 8.3. Final Architecture: Direct Endpoint Tailscale Integration
Given the unresolved TCP handshake failures through the PfSense subnet router, the architecture was modified to guarantee reliable log delivery. 

We abandoned the subnet router approach for the internal logging endpoints. Instead, the final solution was to install the Tailscale VPN client directly on the endpoints themselves:
* **Windows LAN:** Tailscale was installed directly, allowing Winlogbeat to forward Windows Event Logs directly over its own Tailscale tunnel to the SIEM (`100.99.54.59:5044`).
* **Alpine LAN:** Tailscale was installed directly, allowing syslog to send events over the VPN directly to the SIEM.

By moving the VPN encapsulation directly to the originating hosts, we bypassed the PfSense state machine for log forwarding traffic. This resolved the TCP handshake issues immediately and resulted in successful, uninterrupted log ingestion into Elasticsearch.

## 9. SIEM Detection Engineering and TheHive Connector

### 9.1. ElastAlert2 Rule Construction
To bridge the gap between ELK (SIEM) log ingestion and TheHive (SIRP) case creation, ElastAlert2 was deployed as the detection engine. A total of **13 detection rules** were engineered to provide full-spectrum coverage across all infrastructure segments. Each rule was mapped to a relevant framework (MITRE ATT&CK for endpoint threats, OWASP Top 10 for web application threats).

#### 9.1.1. Windows LAN Detection (`windows-logs-*`) — 5 Rules

| Rule File | Detection | MITRE ID | Event ID | Key Fields |
|-----------|-----------|----------|----------|------------|
| `win_bruteforce.yaml` | Brute Force (Failed Logons) | T1110 | 4625 | `source.ip` |
| `win_new_service.yaml` | Malicious Service Installation | T1543 | 7045 | `host.name`, `winlog.event_data.ServiceName` |
| `win_powershell.yaml` | Suspicious PowerShell Execution | T1059.001 | 4104 | `host.name` (keywords: `Invoke-Mimikatz`, `bypass`, `IEX`) |
| `win_admin_group.yaml` | Privilege Escalation | T1098 | 4732 | `host.name`, `winlog.event_data.MemberName` |
| `win_new_user.yaml` | New Account Creation | T1136 | 4720 | `winlog.event_data.TargetUserName`, `host.name` |

#### 9.1.2. Juice Shop DMZ Detection (`juiceshop-docker-*`) — 3 Rules

| Rule File | Detection | OWASP | Key Fields |
|-----------|-----------|-------|------------|
| `juiceshop_sqli.yaml` | SQL Injection | A03:2021 | `access_log.client_ip`, `access_log.request_uri`, `access_log.request_body` |
| `juiceshop_xss.yaml` | Cross-Site Scripting (XSS) | A03:2021 | `access_log.client_ip`, `access_log.request_body`, `access_log.http_referrer` |
| `juiceshop_lfi.yaml` | Directory Traversal / LFI | A01:2021 | `access_log.client_ip`, `access_log.request_uri` |

**Note:** During field mapping, it was discovered that the Logstash pipeline for Juice Shop uses custom field names (`access_log.client_ip`, `access_log.request_uri`, `access_log.request_body`) rather than standard ECS fields. Additionally, Juice Shop (Angular-based) transmits most attack payloads via POST request bodies rather than URL parameters, requiring the rules to scan both `access_log.request_uri` and `access_log.request_body`.

#### 9.1.3. PfSense Firewall Detection (`soc-logs-*`) — 2 Rules

| Rule File | Detection | Key Fields |
|-----------|-----------|------------|
| `pfsense_portscan.yaml` | Blocked Traffic / Port Scan | `src_ip`, `dst_port`, `action` |
| `pfsense_dmz_breakout.yaml` | DMZ-to-LAN Lateral Movement | `src_ip` (172.16.0.*), `dst_ip` (192.168.10.*) |

**Note:** PfSense log fields also use non-standard naming (`src_ip`, `dst_ip`, `action`) as parsed by the custom Logstash `filterlog` pipeline, rather than ECS-standard fields like `source.ip` or `event.action`.

#### 9.1.4. Linux LAN Detection (`linux-lan-logs-*`) — 2 Rules

| Rule File | Detection | Key Fields |
|-----------|-----------|------------|
| `linux_root_login.yaml` | Direct Root SSH Login | `syslog_program`, `syslog_message` |
| `linux_ssh_bruteforce.yaml` | SSH Brute Force | `syslog_program`, `syslog_message` |

#### 9.1.5. Pre-existing Rule (Suricata IDS)

| Rule File | Detection | Key Fields |
|-----------|-----------|------------|
| `suricata_high_severity.yaml` | High Severity IDS Alerts | `alert.signature`, `src_ip`, `dest_ip` |

### 9.2. Troubleshooting TheHive API Connectivity (401 Unauthorized)
During initial testing of the Windows rules (triggering a simulated malicious service via PowerShell), ElastAlert2 successfully queried the logs and matched the threat, but failed to generate the alert in TheHive.
* **Error Encountered:** `401 Client Error: Unauthorized for url: http://<TheHive-IP>:9000/api/alert`
* **Root Cause:** The initial configuration lacked the global `hive_connection` block. After adding it to `config.yaml`, the API key previously generated for Suricata alerts had expired/been revoked.
* **Resolution:** Generated a fresh API key from the target account within TheHive UI and applied it to the global `config.yaml`, ensuring all individual rules globally inherit valid authentication parameters.

### 9.3. ElastAlert2 JSON Field String Formatting
An issue occurred where the generated alert titles in TheHive appeared literally as `New Service on {match[host.name]}` instead of resolving to the actual endpoint hostname (e.g., `DESKTOP-FK7RO72`). 
* **Root Cause:** Logstash parses fields using the Elastic Common Schema (ECS), which heavily utilizes dot notation (`host.name`, `winlog.event_data.IpAddress`). However, ElastAlert2 uses native Python string formatting for rule outputs, which interprets dots as object method calls rather than dictionary keys.
* **Resolution:** Refactored the configuration to mirror the working Suricata connector. Dynamic variables were removed from the `title` and instead populated securely into the description using `alert_text` and `alert_text_args:`. Furthermore, `hive_observable_data_mapping` was implemented in the ElastAlert rules to extract elements like `winlog.event_data.IpAddress` into format-compliant, actionable TheHive Observables, officially enabling automatic Cortex intelligence scanning.

### 9.4. PfSense Firewall Rule Configuration for Detection
To ensure PfSense firewall events are properly forwarded to the ELK stack for ElastAlert2 analysis, the following PfSense firewall rules were configured with **packet logging enabled**:

| Interface | Action | Source | Destination | Logging | Purpose |
|-----------|--------|--------|-------------|---------|---------|
| **DMZ** | Block | DMZ subnets | LAN subnets | ✅ Enabled | Detects lateral movement attempts from compromised DMZ hosts |
| **WAN** | Block | EasyRuleBlockHosts | Any | ✅ Enabled | Detects external port scans and enforces Cortex auto-blocks |

**Key Decision:** Logging was intentionally **disabled** on all `allow` rules (LAN, Tailscale) to prevent flooding the SIEM with millions of legitimate traffic events. Only `block` actions are logged, as these represent unauthorized access attempts — the exact events a SOC analyst needs to investigate.

## 10. Phase 5: Detection Validation Pipeline

To guarantee the reliability of the end-to-end SIEM and SOAR architecture, a formal detection validation phase was conducted. This involved mapping every ElastAlert2 rule to the MITRE ATT&CK framework and simulating the behaviors to verify that alerts successfully escalate into TheHive.

### 10.1 Windows Endpoint Validation (Atomic Red Team)
For the Windows LAN segment, **Atomic Red Team** was deployed. As an industry standard for endpoint behavior simulation, it provided a structured way to execute specific ATT&CK techniques without relying on arbitrary malware. 

The following Atomic tests were executed locally on the Windows endpoint via PowerShell:

| Executed Atomic Test | MITRE ID | Triggered ElastAlert2 Rule(s) |
|----------------------|----------|-------------------------------|
| `T1136.001` (Create Local Account) | T1136, T1098, T1059.001 | `win_new_user.yaml`, `win_admin_group.yaml`, `win_powershell.yaml` |
| `T1543.003` (Windows Service) | T1543 | `win_new_service.yaml` |
| `T1110.001` (Password Guessing) | T1110 | `win_bruteforce.yaml` |

**Result:** Executing just three targeted Atomic simulations successfully synthesized the required logs in Winlogbeat, validating all 5 Windows detection rules simultaneously.

### 10.2 Linux and DMZ Validation (Network Simulation)
Because Atomic Red Team is primarily designed for Endpoint Detection and Response (EDR) validation (focusing on local attacks like `sudo` abuse rather than external network SSH brute forcing), network-level detection rules required direct stimulation:

*   **Linux LAN (`linux-lan-logs-*`):** Validated manually by executing direct `ssh root@<IP>` connections to trigger `linux_root_login.yaml`, and repeated password failures to trigger `linux_ssh_bruteforce.yaml`.
*   **Juice Shop DMZ (`juiceshop-docker-*`):** Developed a custom `dmz-attack-sim.sh` bash toolkit using `curl` to dynamically inject OWASP payloads (SQL Injection, XSS, and LFI) directly against the web application endpoints.

### 10.3 Successful Alert Escalation
The culmination of this phase proved the pipeline's operational integrity. As attacks were simulated on the endpoints and network interfaces, Elasticsearch reliably processed the logs, ElastAlert2 triggered accurately against the MITRE techniques, and the alerts were successfully populated in TheHive interface, awaiting automatic Cortex enrichment.

![TheHive Alert Generation - Windows and Linux Validation](validation-screenshot.png) 
## 11. Phase 6: Cortex Analyzer Catalog Recovery & SOAR Orchestration Hardening

Following the successful Phase 5 detection validation, a deeper audit of the Cortex
analyzer layer and the custom SOAR orchestration script was conducted to close gaps
between "detection working" and "response pipeline production-ready."

### 11.1. Cortex Analyzer Catalog Failure (Root Cause Analysis)

* **The Problem:** Running the VirusTotal analyzer against a live observable returned
  a hard failure: `"Service parameter is missing"`. Investigation in the Cortex UI
  (Organization → Analyzers) revealed a broader issue: all 4 previously configured
  analyzers (`VirusTotal_GetReport_3_1`, `URLhaus_2_0`, `OTXQuery_2_0`,
  `AbuseIPDB_2_0`) were flagged **obsolete**, and the "Available analyzers" list —
  where updated replacements should have appeared — showed **zero** entries.

* **Investigation:** Direct inspection of the running Cortex container
  (`docker exec cortex cat /tmp/cortex-<id>.conf`) confirmed the entrypoint script
  correctly generates the current StrangeBee analyzer catalog URL
  (`https://catalogs.download.strangebee.com/latest/json/analyzers.json`) at
  startup. However, `application.conf` — mounted read-only into the container and
  loaded via `include file(...)` at the end of the generated config — **redefined
  the entire `analyzer {}` block**, overriding the correct catalog URL with a
  stale one (`https://download.thehive-project.org/analyzers.json`, since migrated).

  The same block also declared a local analyzer path
  (`analyzer.path = ["/opt/cortexneurons/analyzers"]`) pointing to a directory that
  did not exist on disk. Cortex's `WorkerSrv` threw a `MalformedURLException`
  (`no protocol: /opt/cortexneurons/analyzers`) while scanning this path, which
  **aborted the entire local worker scan**, explaining why only a single unrelated
  local analyzer (`PfSense_Blocker`) was surviving the scan.

* **The Solution:** Edited `application.conf` to remove the stale `urls` override
  and the nonexistent local `path` entry from both the `analyzer {}` and
  `responder {}` blocks, letting the entrypoint-generated StrangeBee catalog URLs
  take effect uncontested. After restarting the Cortex container and clicking
  "Refresh analyzers," the catalog populated correctly with **277 available
  analyzers**. The 4 obsolete analyzers were disabled and their current-version
  replacements (VirusTotal, AbuseIPDB, URLhaus, and later re-confirmed with OTX)
  were re-enabled and reconfigured with API keys, TLP/PAP limits, and rate limits.

**Key takeaway:** HOCON's `include file(...)` directive loads *after* the
entrypoint-generated config, so any block re-declared in `application.conf`
silently overrides values the entrypoint script computes dynamically (secrets,
job directories, and — critically — the analyzer/responder catalog URLs). Any
future manual edits to `application.conf` must avoid re-declaring `analyzer` or
`responder` blocks unless intentionally overriding the entrypoint's defaults.

### 11.2. SOAR Orchestration Script: From Mock to Real Closed-Loop Pipeline

The Python orchestration script (`e2e_soc_orchestrator.py`) — which drives the full
alert → triage → enrichment → decision → containment loop against the live
TheHive/Cortex API — was progressively hardened:

* **Real analyzer job polling with timeout protection.** The original polling loop
  (`while True: ...`) had no upper bound and could hang indefinitely on a stuck
  Cortex job. Replaced with a `wait_for_analyzer_job()` helper enforcing a
  120-second timeout, printing status transitions (`Waiting` → `InProgress` →
  `Success`/`Failure`) as they occur, and gracefully recovering from transient
  polling errors instead of crashing the script.

* **Full, untruncated report output.** The original implementation truncated
  analyzer reports to 500 characters before printing (`json.dumps(report)[:500]`),
  discarding most of the real VirusTotal/AbuseIPDB payload. Reports are now printed
  in full, with taxonomy/summary tags (e.g. `[malicious] VT:GetReport = 15/90`)
  surfaced separately for quick human scanning.

* **Multi-analyzer enrichment per observable.** Originally the script only ran a
  single hardcoded analyzer (`AbuseIPDB_2_0`) against the first observable found.
  It now fetches the full enabled-analyzer catalog from Cortex, filters by a
  configurable analyzer name list (`VirusTotal_GetReport`, `AbuseIPDB`,
  `AlienVault_OTX`, `URLhaus`), matches each analyzer against the observable's
  `dataType`, and runs **every applicable analyzer against every observable** on
  the case — mirroring the Tier 1 Triage Automation strategy described in Section
  3.5, rather than relying on a single intelligence source per verdict.

* **Real LLM integration for triage and final decision.** The two decision points
  in the pipeline (initial alert triage, and final verdict after enrichment) were
  originally hardcoded mock functions returning a fixed verdict regardless of
  input. Both were rewired to call a real LLM via the **Groq API** (free tier,
  OpenAI-compatible endpoint, `llama-3.3-70b-versatile`), sending the actual alert
  summary and the real, collected Cortex analyzer reports, and parsing a
  structured JSON verdict (`verdict` / `action` / `reason`) back from the model.
  A safe-default fallback (`dismiss` / `none`) was built in for LLM API failures,
  so a rate-limit or network hiccup cannot silently escalate to an automated
  block action.

* **Verification.** Running the hardened pipeline end-to-end against a real
  `JuiceShop Directory Traversal` alert correctly: fetched the alert, triaged it
  as suspicious via the LLM, promoted it to a case, ran all 3 applicable
  analyzers (AbuseIPDB, URLhaus, VirusTotal) against the extracted IP observable,
  collected all 3 real reports, and passed them to the LLM for a final verdict
  — correctly returning `BENIGN` when all three intelligence sources agreed the
  observable (a Tailscale mesh address used for the lab's simulated-attacker path
  per Section 7.6.2) showed no indicators of compromise. This confirms the
  pipeline's decision logic is sound and correctly reflects real threat-intel
  consensus rather than a scripted outcome.

### 11.3. ElastAlert2 Rule Enrichment (Alert Context Depth)

All 12 detection rules (Section 9.1) were reviewed and enriched to carry
significantly more forensic context into TheHive, beyond the original bare-title
alerts:

* **Structured descriptions.** Each rule now builds a multi-field description
  (source IP, request/command details, timestamps, affected host/account) using
  positional `alert_text_args` — consistent with the dotted-field-name workaround
  already discovered for the Suricata/Windows rules in Section 9.3, avoiding
  Python string-formatting errors on ECS-style dotted keys.
* **Severity mapping.** Each rule now explicitly sets `hive_severity` (2–4)
  reflecting its risk level, rather than relying on TheHive's default.
* **MITRE/OWASP tagging.** Every rule now auto-tags its corresponding technique
  or OWASP category (e.g. `MITRE:T1110`, `OWASP:A01:2021`) directly on the
  TheHive alert, making alerts filterable/sortable by framework mapping without
  requiring an analyst to read the free-text description first.
* **Expanded observable extraction.** Rules that previously mapped only a single
  generic observable now extract multiple typed observables where relevant (e.g.
  the Juice Shop SQLi/XSS/LFI rules now extract the request URI and body as
  separate observables alongside the client IP), increasing the enrichment
  surface available to Cortex analyzers in Phase 6.2's multi-analyzer pipeline.
* **Linux SSH source IP extraction.** The `linux_root_login` and
  `linux_ssh_bruteforce` rules originally only captured the raw syslog program
  and message as free text, with no structured IP observable. A Logstash grok
  pattern was added to extract the source IP directly from the sshd log line,
  and both rules were updated to map it as a proper `ip` observable — enabling
  Cortex threat-intel enrichment (AbuseIPDB/VirusTotal/OTX) on SSH brute-force
  and direct-root-login attempts, which was not previously possible.

**Result:** TheHive alerts generated by all 12 rules now carry the forensic detail
an analyst needs to triage without cross-referencing raw Elasticsearch/Kibana
queries, and every rule's extracted observables are structured correctly for
downstream automated Cortex enrichment.
