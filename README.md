# Yalt Inspector
A lightweight, local-first tool for inspecting pfSense firewall behavior.  
Yalt Inspector ingests your pfSense backup configuration and filter logs, normalizes them, and prepares them for rule-to-log comparison. The goal is to detect traffic that violates your expected firewall behavior — unusual passes, unexpected blocks, or events that match no rule at all.

This project is intentionally simple at this stage. It is designed to grow into a homelab-friendly, privacy-respecting log inspector that can monitor pfSense, Pi-hole, Unraid, Docker, and Home Assistant.

---

## Features (v0)
- Parse pfSense XML configuration backup
- Extract firewall and NAT rules into structured Python objects
- Parse pfSense `filter.log` lines (including the `filterlog[PID]:` format)
- Extract interface, protocol, action, IPs, and ports from each log entry
- Normalize log events into Python dataclasses for later analysis

---

## Project Structure

yalt_inspector/
yalt/
parser/
rules.py # Extract firewall/NAT rules from pfSense XML
logs.py # Parse pfSense filterlog lines
engine/
analyzer.py # (coming soon) rule-to-log comparison engine
cli/
run.py # (coming soon) CLI entry point
logs/ # User-provided pfSense log files
test.xml # Optional test pfSense rule XML
README.md

yaml
Copy code

---

## Prerequisites
- Python 3.10+
- Basic understanding of where your pfSense config and logs live

---

## Getting Started

### 1. Install dependencies (none required yet)
This project currently uses only Python's standard library.

### 2. Place your pfSense files
Copy your files into the project directory, for example:

logs/filter.log
config/config.xml

python
Copy code

### 3. Parse your rules (example)
```python
from yalt.parser.rules import parse_pfsense_rules

rules = parse_pfsense_rules("config/config.xml")
print(rules)
4. Parse firewall logs (example)
python
Copy code
from yalt.parser.logs import parse_log_file

logs = parse_log_file("logs/filter.log")
print(len(logs))
print(logs[0])
Once parsed, rules and logs are ready for inspection by the analyzer module.

Log Format Support
Yalt Inspector currently supports pfSense filterlog lines in the form:

less
Copy code
Nov 22 17:10:00 pfSense filterlog[64545]: 126,,,1761156909,igb1.20,match,block,in,...
The parser extracts:

interface

action (pass/block)

protocol (tcp/udp/icmp)

src IP

dst IP

src port

dst port

Support for additional formats, NAT logs, and verbose mode will be added later.

Upcoming Features
Analyzer engine (rule-to-log correlation)

Detection of traffic that violates rules

Identification of unexpected WAN egress (camera VLAN, IoT, etc.)

NAT inspection logic

CLI interface (yalt inspect …)

Exportable reports

Support for Pi-hole, Unraid, Docker, and Home Assistant logs

Roadmap
Rule ↔ Log Analyzer
Detect anomalies such as:

No matching rule

Action mismatch (rule says block, log shows pass)

Unexpected egress

NAT forwarding inconsistencies

Pluggable log sources
Extend ingestion beyond pfSense.

Optional local web dashboard
Zero cloud dependencies.

Automated log retrieval
SCP, syslog receiver, or API-based pulling.

License
This project is currently under personal development.
License terms will be finalized once the project matures.

Status
Active development.
Version: v0.1-pre
