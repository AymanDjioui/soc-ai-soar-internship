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
