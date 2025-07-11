# SIEM Deployment with Suricata, Filebeat, and Elastic Stack

## Project Overview

This SIEM solution integrates the following components:

- **Elasticsearch** for log storage and indexing  
- **Logstash** for log processing and enrichment  
- **Kibana** for log visualization and analysis  
- **Filebeat** for log shipping  
- **Suricata** as the Network Intrusion Detection System (NIDS)

---

## Architecture

./diagrams/Infrastructure Architecture.png

---

## Key Features

- Full Elastic Stack deployment on Ubuntu Server 22.04
- Suricata NIDS for monitoring and rule-based alerting
- Filebeat shipping logs from Suricata to Logstash
- Logstash pipelines for parsing Suricata alerts
- Kibana dashboards for visual threat analysis
- Email alert integration using ElastAlert

---
