# SOC-Linux-SIEM-Lab

Practical lab for SIEM pipeline troubleshooting, SSH brute-force attack detection, and SOC log analysis.

## Author
* **Name:** Nacho
* **Professional Focus:** Cybersecurity Analysis | Technical Auditing
* **Certifications:** Cisco Certified Support Technician (CCST) 100-160

---

## 1. Executive Summary
This technical project documents the integration, troubleshooting, and analysis of a centralized log management pipeline (SIEM) to detect unauthorized access attempts. After configuring and debugging the log ingestion layer on an Ubuntu server, a controlled manual brute-force simulation was executed targeting the SSH daemon. The resulting security events were centralizing into Wazuh/OpenSearch, validating the analyst's capability to perform Threat Hunting, interpret alerts, and extract key Indicators of Compromise (IoCs).

---

## 2. Environment & Architecture
* **Hypervisor:** UTM Engine (Native Apple Silicon Virtualization)
* **Host Hardware:** MacBook Air M1 (2020), 16 GB RAM
* **Target Server (Victim):** Ubuntu Server ARM64 (`pcnacho`)
* **SIEM Platform:** Wazuh Manager / OpenSearch Indexer (All-in-one architecture)
* **Log Shipper:** Filebeat 7.10.2 (Secured via TLS using `indexer.pem` and `root-ca.pem`)
* **Framework Mapping:** MITRE ATT&CK T1110 (Credential Access / Brute Force)

---

## 3. SIEM Pipeline Troubleshooting (Engineering Phase)
Before analyzing alerts, the log shipper (`filebeat`) encountered a deployment failure (`Active: failed`). A local technical audit was performed to restore the telemetry:

1. **Output Deficit:** The original setup lacked destination directives. A secure routing output block was engineered toward OpenSearch (`https://192.168.64.5:9200`).
2. **Cryptographic Alignment:** Mismatched TLS certificate paths were corrected to map the existing infrastructure keys (`indexer.pem` and `indexer-key.pem`), resolving the `no such file or directory` initialization error.
3. **Module Restoration:** The native Wazuh parsing definitions were missing. The official module package was manually deployed into `/usr/share/filebeat/module` to enable log parsing.

Operational validation was achieved via the binary config test:
```bash
nacho@pcnacho:~$ sudo filebeat test config
Config OK
```

---

## 4. Attack Simulation Phase
To validate the detection capabilities of the SIEM platform and verify the end-to-end log delivery pipeline, a controlled credential-guessing simulation was executed. 

The attack vector targeted the SSH daemon (listening on the default Port 22) of the target server (`pcnacho`). The simulation focused on replicating opportunistic perimeter scanning—a common phase in threat actor reconnaissance where automated scripts attempt to identify weak or default accounts on internet-facing assets.

The interaction was performed by forcing authentication requests using an explicit non-existent identity:
* **Target Identity:** `usuario_falso`
* **Mechanism:** Connection attempts via terminal, forcing the SSH daemon to process password validation failures and trigger the core operating system's security auditing mechanisms.

This simulation successfully generated the authentication anomalies required to test if the newly repaired Filebeat shipper could capture, parse, and transmit telemetry under load.

---

## 5. SOC Investigation & Log Analysis
Following the infrastructure remediation and the attack simulation, security events were successfully ingested by the SIEM platform, breaking the dashboard flatline and registering **441 total alerts**, including the specific unauthorized interaction indicators.

<img width="772" height="186" alt="Captura de pantalla 2026-06-30 a las 20 40 18" src="https://github.com/user-attachments/assets/d4f25860-005d-45f7-a939-10330318334e" />

### Deep-Dive Indicator Extraction (JSON Parsing)
Using Dashboard Query Language (DQL), the events were isolated under the explicit signature **Rule ID: 5710**. Granular document analysis within the SIEM interface allowed the extraction of the following structural data fields and Indicators of Compromise (IoCs):

* **`rule.id`:** `5710`
* **`rule.description`:** `sshd: Attempt to login using a non-existent user`
* **`rule.level`:** `5` (Security alert indicating low-severity anomalous behavior)
* **`agent.name`:** `pcnacho` (Target system endpoint identifier)
* **`data.srcip`:** `192.168.64.1` (Source IP identifying the internal network gateway interface)
* **`data.srcuser`:** `usuario_falso` (The specific non-existent identity targeted during the simulation)
* **`decoder.name`:** `sshd` (The engine component that successfully parsed the raw log syntax)

```json
// Full log metadata extracted from document details during the investigation
Jun 30 14:32:28 pcnacho sshd[4495]: Failed password for invalid user usuario_falso from 192.168.64.1 port 52171 ssh2
```

---

## 6. Proposed Mitigation & Incident Remediation Strategy
From a SOC Analysis perspective, establishing swift containment and hardening countermeasures is critical to minimize the asset's attack surface. The following tactical recommendations are proposed based on the extracted IoCs:

1. **Automated Containment:** Leverage **Fail2Ban** (as implemented in previous framework deployments) to dynamically block source IPs at the firewall layer after 5 failed authentication attempts.
2. **Endpoint Hardening (SSH Bastioning):**
   * Enforce `PermitRootLogin no` in `/etc/ssh/sshd_config` to eliminate direct administrative brute-force vectors.
   * Disable password-based authentication entirely (`PasswordAuthentication no`) and enforce exclusive SSH Key-Based cryptographic access.
   * Shift the service from the standard port `22` to a non-standard port (e.g., `2222`) to eliminate automated, opportunistic perimeter scanning.
3. **Network Layer Isolation:** Restrict direct external access to the management interface by shifting the SSH daemon behind a secure **VPN** infrastructure.

---

### Conclusion & Next Steps
Through this operational lab, the SIEM ingestion pipeline was successfully debugged, restored, and validated under realistic attack conditions. The accurate parsing and extraction of the **Rule ID: 5710** event signature confirms that the security monitoring baseline is fully operational. The next phase will focus on enforcing the SSH hardening policies to transition the asset from passive monitoring to a robust, defensive posture.
