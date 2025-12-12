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

    def generate_report(self):
        """
        Scans the data directory for CVE files, processes them, and prepares the report data.
        """
        print("[+] Generating report...")
        cve_files = [f for f in os.listdir(self.data_dir) if f.startswith('cves_') and f.endswith('.json')]

        if not cve_files:
            print("[!] No CVE files found in the data directory.")
            self.report_data = pd.DataFrame()
            return

        all_cves = []
        for file in cve_files:
            with open(os.path.join(self.data_dir, file), 'r') as f:
                all_cves.extend(json.load(f))

        if not all_cves:
            print("[!] No CVEs found in the files.")
            self.report_data = pd.DataFrame()
            return

        df = pd.DataFrame(all_cves)
        df.drop_duplicates(subset='cve_id', inplace=True)
        df['published_date'] = pd.to_datetime(df['published_date'])
        df.sort_values(by='published_date', ascending=False, inplace=True)

        self.report_data = df
        print(f"[+] Processed {len(self.report_data)} unique CVEs.")

    def save_report(self):
        """
        Saves the processed data to a Markdown file.
        """
        if self.report_data is None or self.report_data.empty:
            print("[!] No data to save.")
            return

        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

        today_str = datetime.now().strftime('%Y-%m-%d')
        report_filename = os.path.join(self.reports_dir, f"Weekly_Threat_Report_{today_str}.md")

        with open(report_filename, 'w') as f:
            f.write(f"# Threat Intelligence Report - {today_str}\n")
            f.write(f"## Executive Summary\n")
            f.write(f"This report contains {len(self.report_data)} vulnerabilities collected from various sources.\n\n")
            f.write("## High Priority Vulnerabilities\n")
            f.write("- (Placeholder for high-priority CVEs)\n\n")
            f.write("## Detailed CVE List\n")

            for index, row in self.report_data.iterrows():
                f.write(f"### {row['cve_id']}\n")
                f.write(f"**Status:** {row['vuln_status']}\n")
                f.write(f"**Published:** {row['published_date'].strftime('%Y-%m-%d')}\n")
                f.write(f"**Description:** {row['description']}\n")
                f.write("---\n")

        print(f"[+] Report saved to {report_filename}")

if __name__ == "__main__":
    generator = ReportGenerator()
    generator.generate_report()
    generator.save_report()
