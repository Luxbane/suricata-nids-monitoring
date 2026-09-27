# Suricata NIDS Monitoring Lab

Enterprise-style Network Security Monitoring Lab built with GNS3, Cisco networking, Suricata IDS, Prometheus, and Grafana.

The project demonstrates how network traffic can be mirrored from a switch to a dedicated monitoring interface, inspected by Suricata, exported as Prometheus metrics, and visualized through Grafana.

---

## Overview

This lab simulates a small enterprise network with separate systems for:

* Network routing
* Network traffic generation and security testing
* Application/server services
* Security monitoring
* Infrastructure monitoring

The main security monitoring pipeline is:

```text
Kali Linux
    │
    │ Network traffic / security testing
    ▼
  SW1
    │
    ├──────────────► Ubuntu Server
    │
    │ SPAN / Port Mirroring
    ▼
Monitoring VM
    │
    │ ens4
    ▼
Suricata IDS
    │
    │ eve.json
    ▼
Suricata Prometheus Exporter
    │
    │ :9917
    ▼
Prometheus
    │
    ▼
Grafana
```

The monitoring VM uses two network interfaces:

* `ens3` — management/monitoring network
* `ens4` — dedicated SPAN traffic capture interface

This separation allows the monitoring system to collect mirrored traffic without using its management interface for packet inspection.

---

## Objectives

The objectives of this project are to demonstrate practical experience with:

* Cisco networking and SPAN/port mirroring
* Linux network configuration
* Network Intrusion Detection Systems (NIDS)
* Suricata rule management
* Network traffic inspection
* Prometheus monitoring
* Custom Prometheus exporters
* Grafana visualization
* Systemd service management
* Git and GitHub-based infrastructure documentation

---

## Network Topology

```text
                         ┌──────────────┐
                         │      R1      │
                         │    Router    │
                         │     SNMP     │
                         │ 10.10.10.1   │
                         └──────┬───────┘
                                │
                             Gi0/0
                                │
                         ┌──────▼───────┐
                         │     SW1      │
                         │     L2/L3    │
                         └───┬────┬────┬┘
                             │    │    │
                          Gi0/1 Gi0/2 Gi0/3
                             │    │    │
                             │    │    │
                        ┌────▼┐ ┌─▼────┐ ┌──────────────┐
                        │Kali │ │Ubuntu │ │  Monitoring  │
                        │ .22 │ │Server │ │     VM       │
                        │     │ │  .23  │ │   .24        │
                        └─────┘ └───────┘ └──────┬───────┘
                                                  │
                                             ens3 │ ens4
                                                  │
                                            Management
                                            SPAN Capture
```

### SPAN Path

The switch mirrors traffic from the Kali-facing interface to the dedicated monitoring interface:

```text
Kali
  │
  │ Gi0/1
  ▼
 SW1
  │
  │ SPAN
  ▼
Monitoring VM ens4
  │
  ▼
Suricata
```

---

## IP Addressing

| Device        | Interface |       IP Address | Role                    |
| ------------- | --------- | ---------------: | ----------------------- |
| R1            | G0/0      |  `10.10.10.1/24` | Router / SNMP target    |
| Kali Linux    | eth0      | `10.10.10.22/24` | Security testing        |
| Ubuntu Server | eth0      | `10.10.10.23/24` | Server / SNMP target    |
| Monitoring VM | ens3      | `10.10.10.24/24` | Monitoring management   |
| Monitoring VM | ens4      |             SPAN | Suricata packet capture |

The monitoring VM's `ens4` interface is intentionally used as a dedicated capture interface and does not require a normal management IP address.

---

## Technologies

| Technology            | Purpose                                    |
| --------------------- | ------------------------------------------ |
| GNS3                  | Network simulation and lab orchestration   |
| Cisco IOS             | Routing and switching                      |
| Kali Linux            | Security testing and traffic generation    |
| Ubuntu Server         | Application/server workload                |
| Suricata 7.0.3        | Network IDS                                |
| Suricata ET Rules     | Threat/signature detection                 |
| Custom Suricata Rules | Lab-specific detection                     |
| Python                | Custom Prometheus exporter                 |
| Prometheus            | Metrics collection                         |
| SNMP Exporter         | Network infrastructure monitoring          |
| Grafana               | Monitoring visualization                   |
| systemd               | Service management                         |
| Git / GitHub          | Configuration and documentation management |

---

## Monitoring Architecture

There are two monitoring pipelines in this lab.

### Infrastructure Monitoring

```text
R1 / Ubuntu Server
        │
       SNMP
        │
        ▼
 SNMP Exporter
        │
        ▼
 Prometheus
        │
        ▼
     Grafana
```

This pipeline monitors infrastructure metrics such as interface status, RX/TX traffic, and interface errors.

### Security Monitoring

```text
Mirrored Network Traffic
        │
        ▼
     Suricata
        │
        ▼
     eve.json
        │
        ▼
Custom Python Exporter
        │
      :9917
        │
        ▼
    Prometheus
        │
        ▼
      Grafana
```

---

## Suricata

Suricata 7.0.3 is configured as the network IDS on the monitoring VM.

The capture interface is:

```text
ens4
```

The monitored network is:

```text
HOME_NET = 10.10.10.0/24
```

The active AF_PACKET configuration is:

```yaml
af-packet:
  - interface: ens4
```

Suricata writes events to:

```text
/var/log/suricata/eve.json
```

The configuration is available in:

```text
configs/suricata/suricata.yaml
```

---

## Custom Detection Rule

A custom Suricata rule was created to detect an HTTP request containing the `Nmap` User-Agent.

```text
alert http $HOME_NET any -> $HOME_NET any (msg:"LAB Nmap User-Agent Detected"; flow:established,to_server; http.user_agent; content:"Nmap"; nocase; classtype:attempted-recon; sid:1000001; rev:1;)
```

The rule is stored in:

```text
configs/suricata/local.rules
```

### Detection Test

A test request was generated using:

```bash
curl -A "Nmap" http://10.10.10.24:3000
```

Suricata generated the following signature:

```text
LAB Nmap User-Agent Detected
```

with SID:

```text
1000001
```

The alert was subsequently exposed through the Prometheus exporter.

---

## Suricata Prometheus Exporter

A custom Python exporter was developed to read Suricata's `eve.json` and expose selected security events as Prometheus metrics.

Exporter source:

```text
configs/exporter/suricata_exporter.py
```

The exporter listens on:

```text
0.0.0.0:9917
```

Metrics endpoint:

```text
/metrics
```

Example:

```bash
curl http://localhost:9917/metrics
```

Important metrics include:

```text
suricata_events_total
suricata_alerts_total
suricata_alerts_by_signature_total
suricata_alerts_by_category_total
```

Example signature metric:

```text
suricata_alerts_by_signature_total{signature="LAB Nmap User-Agent Detected"} 11
```

The exporter is managed using systemd:

```text
configs/exporter/suricata-exporter.service
```

---

## Prometheus

Prometheus scrapes the custom Suricata exporter using:

```text
10.10.10.24:9917
```

Configuration:

```text
configs/prometheus/prometheus.yml
```

Prometheus also collects SNMP metrics from network infrastructure and the Ubuntu Server.

The resulting architecture combines:

```text
Infrastructure Metrics
        +
Security Detection Metrics
        │
        ▼
    Prometheus
        │
        ▼
     Grafana
```

---

## Grafana

Grafana provides the visualization layer for the monitoring platform.

The dashboard includes infrastructure and security monitoring information such as:

* Target selection
* Interface status
* RX traffic
* TX traffic
* Interface errors
* Suricata alert count
* Suricata signatures
* Alert categories

The exported dashboard is stored at:

```text
grafana/dashboard.json
```

Screenshots will be added under:

```text
docs/images/
```

---

## Cisco SPAN Configuration

SW1 mirrors traffic from the Kali-facing interface to the dedicated monitoring interface.

Configuration:

```cisco
monitor session 1 source interface Gi0/1 both
monitor session 1 destination interface Gi1/0
```

This allows the monitoring VM to receive a copy of selected network traffic without becoming inline with the production traffic path.

Configuration reference:

```text
configs/cisco/span-config.txt
```

---

## Validation

### Verify Suricata

```bash
sudo systemctl status suricata
```

### Verify Suricata Configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Verify SPAN Traffic

```bash
sudo tcpdump -ni ens4
```

Traffic generated by Kali toward the Ubuntu Server should be visible on the monitoring interface.

### Verify Suricata Alerts

```bash
sudo tail -f /var/log/suricata/eve.json
```

### Verify Exporter

```bash
curl -s http://localhost:9917/metrics | grep suricata_alerts
```

### Verify Prometheus

Prometheus should show the Suricata exporter target as:

```text
UP
```

Target:

```text
10.10.10.24:9917
```

### Verify Grafana

The Grafana dashboard should display the metrics collected by Prometheus.

---

## Example Detection Flow

The complete detection workflow is:

```text
1. Kali generates test traffic
           │
           ▼
2. SW1 forwards normal traffic
           │
           ├──────────────► Ubuntu Server
           │
           └── SPAN ──────► Monitoring VM
                                  │
                                  ▼
                              Suricata
                                  │
                                  ▼
                              eve.json
                                  │
                                  ▼
                         Python Exporter :9917
                                  │
                                  ▼
                              Prometheus
                                  │
                                  ▼
                               Grafana
```

For the custom HTTP detection:

```text
Kali
 │
 │ HTTP request with User-Agent: Nmap
 ▼
Ubuntu Server / HTTP service
 │
 │ mirrored packet
 ▼
Suricata
 │
 │ SID 1000001
 ▼
eve.json
 │
 ▼
Prometheus Exporter
 │
 ▼
suricata_alerts_by_signature_total
 │
 ▼
Grafana
```

---

## Repository Structure

```text
suricata-nids-monitoring/
├── .gitignore
├── configs/
│   ├── cisco/
│   │   └── span-config.txt
│   ├── exporter/
│   │   ├── suricata-exporter.service
│   │   └── suricata_exporter.py
│   ├── prometheus/
│   │   └── prometheus.yml
│   └── suricata/
│       ├── local.rules
│       └── suricata.yaml
├── grafana/
│   └── dashboard.json
└── docs/
    └── images/
```

---

## Reproduction

The lab can be reproduced using the following general sequence:

1. Deploy the network topology in GNS3.
2. Configure the Cisco router and switch.
3. Configure the Ubuntu Server.
4. Configure the Monitoring VM with separate management and capture interfaces.
5. Configure Cisco SPAN.
6. Install and configure Suricata.
7. Configure Suricata rules.
8. Deploy the custom Suricata Prometheus exporter.
9. Configure Prometheus.
10. Import the Grafana dashboard.
11. Generate test traffic from Kali.
12. Verify packet capture, Suricata alerts, Prometheus metrics, and Grafana visualization.

Detailed configuration files are provided in the `configs/` directory.

---

## Security Considerations

This repository contains configuration files for a controlled GNS3 laboratory environment.

Runtime data such as:

* `eve.json`
* Suricata logs
* temporary Python bytecode
* system-specific runtime files

is intentionally excluded from the repository.

Credentials, tokens, and other secrets should never be committed to the repository.

---

## Author

**Luxbane**

GitHub:

https://github.com/Luxbane
