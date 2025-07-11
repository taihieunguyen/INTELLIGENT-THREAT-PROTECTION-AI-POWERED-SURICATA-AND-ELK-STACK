# SIEM Deployment with Suricata, Filebeat, and Elastic Stack

## Project Overview

This SIEM solution integrates the following components:

- **Elasticsearch** for log storage and indexing  
- **Logstash** for log processing and enrichment  
- **Kibana** for log visualization and analysis  
- **Filebeat** for log shipping  
- **Suricata** as the Network Intrusion Detection System (NIDS)
- **AI-Based IDS** for monitoring network traffic
- **Winlogbeat** for collecting and forwarding Windows event logs  

---

## Architecture

 ![Image Alt](https://github.com/taihieunguyen/Intelligent-threat-protection-AI-powered-Suricata-and-ELK-stack/blob/main/diagrams/Infrastructure%20Architecture.png?raw=true)


---

## Key Features

- Real-time log ingestion and visualization
- AI-enhanced IOC classification and rule generation
- Detection of brute-force and XSS attacks
- Email alerting using ElastAlert
- Integration with Windows log sources via Winlogbeat
- Custom Kibana dashboards for Suricata events

---

## Repository Structure

├── elasticsearch-config/ # Configuration for Elasticsearch
├── logstash-config/ # Logstash pipeline and filter files
├── kibana-config/ # Exported Kibana dashboards
├── filebeat-config/ # Filebeat configuration files
├── winlogbeat-config/ # Winlogbeat config for Windows logs
├── suricata-config/ # Custom rules and YAML config for Suricata
├── ai-module/ # Python code for AI log classification
├── demo/ # Attack scripts (e.g., brute force, XSS)
└── README.md # Project documentation

## Installation Guide

### Step 1: Clone the Repository

```bash
git clone https://github.com/taihieunguyen/Intelligent-threat-protection-AI-powered-Suricata-and-ELK-stack.git
cd Intelligent-threat-protection-AI-powered-Suricata-and-ELK-stack
Step 2: Set Up Suricata
Install Suricata on Ubuntu

Apply custom rules in suricata-config/

Ensure output to eve.json is enabled

Step 3: Configure Filebeat
Modify filebeat.yml to read from Suricata eve.json

Enable modules as needed

Start Filebeat service

Step 4: Configure Winlogbeat
Install Winlogbeat on Windows machines

Use provided winlogbeat.yml to forward logs

Start Winlogbeat service

Step 5: Set Up Logstash
Import pipelines from logstash-config/

Configure inputs for Filebeat and Winlogbeat

Start Logstash

Step 6: Load Kibana Dashboards
Start Kibana

Import dashboards from kibana-config/

Step 7: Run AI Module
bash
Copy
Edit
cd ai-module/
python ai_search.py
Classifies IOCs and generates Suricata rule recommendations

Step 8: Enable Alerting
Install and configure ElastAlert

Define alert rules for critical events

Demonstration Scenarios
Demo 1: XSS attack detection on web server with Suricata rule

Demo 2: Brute-force password attack and detection

Demo 3: Email alert triggered via ElastAlert

Demo 4: Real-time Windows log monitoring with Winlogbeat

Demo 5: Web-based AI log search tool

System Requirements
Ubuntu Server 22.04

Python 3.8+

Suricata

Elasticsearch 8.x

Logstash 8.x

Kibana 8.x

Filebeat and Winlogbeat



Contact
Author: Nguyễn Tài Hiếu
Email: taihieunguyen004@gmail.com
University of Information Technology – VNU-HCM
