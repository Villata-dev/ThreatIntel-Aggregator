import os
import json
import pandas as pd
from datetime import datetime

class ReportGenerator:
    """
    Aggregates raw JSON data and generates a clean, structured report
    suitable for LLM analysis.
    """
    def __init__(self, data_dir="data/", reports_dir="reports/"):
        """
        Initializes the ReportGenerator.

        :param data_dir: The directory where the raw JSON files are located.
        :param reports_dir: The directory where the generated reports will be saved.
        """
        self.data_dir = data_dir
        self.reports_dir = reports_dir
        self.report_data = None
        self.news_data = None

    def generate_report(self):
        """
        Scans the data directory for CVE and news files, processes them, and prepares the report data.
        """
        print("[+] Generating report...")
        # Process CVEs
        cve_files = [f for f in os.listdir(self.data_dir) if f.startswith('cves_') and f.endswith('.json')]
        if not cve_files:
            print("[!] No CVE files found in the data directory.")
            self.report_data = pd.DataFrame()
        else:
            all_cves = []
            for file in cve_files:
                with open(os.path.join(self.data_dir, file), 'r') as f:
                    all_cves.extend(json.load(f))
            if not all_cves:
                print("[!] No CVEs found in the files.")
                self.report_data = pd.DataFrame()
            else:
                df = pd.DataFrame(all_cves)
                df.drop_duplicates(subset='cve_id', inplace=True)
                df['published_date'] = pd.to_datetime(df['published_date'])
                df.sort_values(by='published_date', ascending=False, inplace=True)
                self.report_data = df
                print(f"[+] Processed {len(self.report_data)} unique CVEs.")

        # Process news
        news_files = [f for f in os.listdir(self.data_dir) if f.startswith('news_') and f.endswith('.json')]
        if not news_files:
            print("[!] No news files found in the data directory.")
        else:
            # Get the latest news file
            latest_news_file = max(news_files, key=lambda f: os.path.getmtime(os.path.join(self.data_dir, f)))
            with open(os.path.join(self.data_dir, latest_news_file), 'r') as f:
                self.news_data = json.load(f)
                print(f"[+] Loaded news from {latest_news_file}.")

    def save_report(self):
        """
        Saves the processed data to a Markdown file.
        """
        if (self.report_data is None or self.report_data.empty) and not self.news_data:
            print("[!] No data to save.")
            return

        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

        today_str = datetime.now().strftime('%Y-%m-%d')
        report_filename = os.path.join(self.reports_dir, f"Weekly_Threat_Report_{today_str}.md")

        with open(report_filename, 'w') as f:
            f.write(f"# Threat Intelligence Report - {today_str}\n")
            f.write(f"## Executive Summary\n")
            if self.report_data is not None:
                f.write(f"This report contains {len(self.report_data)} vulnerabilities collected from various sources.\n\n")
            else:
                f.write("This report contains no new CVEs.\n\n")

            f.write("## High Priority Vulnerabilities\n")
            f.write("- (Placeholder for high-priority CVEs)\n\n")

            if self.report_data is not None and not self.report_data.empty:
                f.write("## Detailed CVE List\n")
                for index, row in self.report_data.iterrows():
                    f.write(f"### {row['cve_id']}\n")
                    f.write(f"**Status:** {row['vuln_status']}\n")
                    f.write(f"**Published:** {row['published_date'].strftime('%Y-%m-%d')}\n")
                    f.write(f"**Description:** {row['description']}\n")
                    f.write("---\n")

            if self.news_data:
                f.write("## Industry News\n")
                for source, articles in self.news_data.items():
                    f.write(f"### {source}\n")
                    for article in articles:
                        f.write(f"- [{article['title']}]({article['link']})\n")
                    f.write("\n")

        print(f"[+] Report saved to {report_filename}")

if __name__ == "__main__":
    generator = ReportGenerator()
    generator.generate_report()
    generator.save_report()
