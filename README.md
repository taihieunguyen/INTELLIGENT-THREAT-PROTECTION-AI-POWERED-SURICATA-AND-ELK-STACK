# Intelligent threat protection AI powered Suricata and ELK stack

## Project Overview

This project implements a Security Information and Event Management (SIEM) solution that integrates Suricata, Filebeat, and the Elastic Stack to provide real-time network threat detection, log management, and advanced analytics. The solution leverages AI-based Intrusion Detection System (IDS) capabilities for enhanced threat identification and response.

Key components include:

- **Elasticsearch**: Centralized log storage and indexing for efficient search and retrieval.
- **Logstash**: Log processing, parsing, and enrichment for structured data pipelines.
- **Kibana**: Visualization and analysis platform for exploring logs and creating dashboards.
- **Filebeat**: Lightweight log shipper for forwarding logs to Elasticsearch or Logstash.
- **Suricata**: High-performance Network Intrusion Detection System (NIDS) for real-time traffic monitoring.
- **AI-Based IDS**: Machine learning model for intelligent threat detection and IOC (Indicator of Compromise) classification.
- **Winlogbeat**: Collects and forwards Windows event logs for comprehensive system monitoring.

---

## Architecture

The following diagram illustrates the infrastructure and data flow of the SIEM solution:

![Infrastructure Architecture](https://github.com/taihieunguyen/Intelligent-threat-protection-AI-powered-Suricata-and-ELK-stack/blob/main/diagrams/Infrastructure%20Architecture.png?raw=true)

---

## Key Features

- **Real-time Log Ingestion and Visualization**: Collect, process, and visualize logs in real-time using Filebeat, Logstash, and Kibana.
- **AI-Enhanced Threat Detection**: Machine learning model for classifying IOCs and generating dynamic detection rules.
- **Attack Detection**: Identifies brute-force attacks, XSS (Cross-Site Scripting) attacks, and other malicious activities.
- **Email Alerting**: Configurable email notifications for critical alerts using ElastAlert.
- **Windows Log Integration**: Collects and processes Windows event logs via Winlogbeat for comprehensive monitoring.
- **Custom Kibana Dashboards**: Pre-built dashboards for analyzing Suricata events and network traffic patterns.

---

## Repository Structure

- **/configs/**: Configuration files for Elasticsearch, Kibana, Filebeat, and Winlogbeat to streamline setup and deployment.
- **/diagrams/**: Architectural diagrams, including Infrastructure and Application Architecture.
- **/model/**: Machine learning models and scripts for training the AI-based IDS.
- **/report/**: Documentation, analysis reports, and performance metrics for the SIEM system.

---

## Prerequisites

To deploy this SIEM solution, ensure the following are installed:

- Elasticsearch 
- Logstash 
- Kibana 
- Filebeat 
- Winlogbeat  (for Windows environments)
- Suricata 
- Python 3.x (for AI model training and inference)

---

## Usage

- **Monitoring**: Use Kibana to explore logs, visualize Suricata alerts, and monitor network traffic.
- **Threat Detection**: The AI-based IDS will classify IOCs and generate rules for Suricata.
- **Alerting**: Receive email notifications for detected threats via ElastAlert.
- **Windows Events**: Analyze Windows event logs through Kibana dashboards for system-level insights.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

---

## Contact

For questions or support, please open an issue on the GitHub repository or contact the maintainer at [taihieunguyen004@gmail.com].
