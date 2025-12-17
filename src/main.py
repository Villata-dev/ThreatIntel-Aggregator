import logging
import os
import sys

# Add the project root to the Python path to allow for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.collectors.cve_collector import CVECollector
from src.collectors.rss_collector import RSSCollector
from src.processors.report_generator import ReportGenerator

def main():
    """
    Main function to orchestrate the CVE data collection and report generation pipeline.
    """
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info("Starting the Threat Intel Aggregator pipeline...")

    try:
        # Step 1: Collect CVEs
        logging.info("Step 1: Collecting CVEs...")
        cve_collector = CVECollector()
        recent_cves = cve_collector.fetch_recent_cves()
        if recent_cves:
            # Ensure the data directory exists before saving
            if not os.path.exists('data'):
                os.makedirs('data')
            cve_collector.save_to_file(recent_cves)
        logging.info("Step 1: CVE collection complete.")

        # Step 2: Collect News
        logging.info("Step 2: Collecting news...")
        feeds = {
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
        }
        rss_collector = RSSCollector(feeds)
        news = rss_collector.fetch_news(limit=5)
        if news:
            if not os.path.exists('data'):
                os.makedirs('data')
            rss_collector.save_news(news)
        logging.info("Step 2: News collection complete.")

        # Step 3: Generate Report
        logging.info("Step 3: Generating report...")
        report_generator = ReportGenerator()
        report_generator.generate_report()
        report_generator.save_report()  # This method handles report directory creation
        logging.info("Step 3: Report generation complete.")

        logging.info("Threat Intel Aggregator pipeline finished successfully.")

    except Exception as e:
        logging.error(f"An error occurred during the pipeline execution: {e}", exc_info=True)

if __name__ == "__main__":
    main()
