# ThreatIntel-Aggregator

## Project Overview

ThreatIntel-Aggregator is a powerful, scalable pipeline designed to collect the latest threat intelligence from various sources, including CVE databases and security news RSS feeds. It processes this information into a structured Markdown report, ready for analysis and integration with external tools like NotebookLM. By automating the collection and aggregation of security data, this project helps security analysts, researchers, and enthusiasts stay ahead of emerging threats.

## Architecture

The project follows a simple yet effective data processing pipeline:

1.  **Collectors**: These scripts are responsible for fetching raw data from external sources.
    *   `cve_collector.py`: Fetches the latest CVEs from the NIST National Vulnerability Database (NVD).
    *   `rss_collector.py`: Gathers security news from various RSS feeds, such as The Hacker News and BleepingComputer.

2.  **Processor**: The collected data is then processed into a clean, unified format.
    *   `report_generator.py`: Consolidates the data from all collectors into a single, well-structured Markdown report.

3.  **Integration**: The final report is designed for easy import into analytical tools.
    *   **NotebookLM**: The Markdown output can be seamlessly integrated with NotebookLM for further analysis, correlation, and insight generation.

## Setup Guide

### Prerequisites

- Python 3.10+
- Docker and Docker Compose (for containerized execution)

### Environment Variables

To properly connect to the NIST NVD API, you need to set up an environment variable for your API key.

1.  **Create a `.env` file** in the root directory of the project.
2.  **Add your NIST API key** to the file as follows:

    ```
    NIST_API_KEY="YOUR_API_KEY_HERE"
    ```

    *Note: You can obtain a free API key from the [NIST NVD website](https://nvd.nist.gov/developers/request-an-api-key).*

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── weekly-schedule.yml
├── data/
│   └── .gitkeep
├── docker/
│   └── .gitkeep
├── logs/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── src/
│   ├── collectors/
│   │   ├── cve_collector.py
│   │   └── rss_collector.py
│   ├── processors/
│   │   └── report_generator.py
│   └── main.py
├── tests/
├── .gitignore
├── Dockerfile
├── LICENSE
├── README.md
├── docker-compose.yml
└── requirements.txt
```

## Running the Project

You can run the ThreatIntel-Aggregator in two ways: manually with Python or using Docker.

### Manual Execution

1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the main script**:
    ```bash
    python src/main.py
    ```

### Docker Execution

1.  **Build and run the Docker container**:
    ```bash
    docker-compose up
    ```

    This command builds the Docker image and runs the container in attached mode. To run it in the background, use `docker-compose up -d`.
