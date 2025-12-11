import os
import json
import unittest
import pandas as pd
from datetime import datetime, timedelta
from src.processors.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    """
    Unit tests for the ReportGenerator class.
    """
    def setUp(self):
        """
        Set up the test environment before each test.
        """
        self.data_dir = "test_data/"
        self.reports_dir = "test_reports/"
        os.makedirs(self.data_dir, exist_ok=True)

        # Create dummy CVE data
        self.cve_data_1 = [
            {"cve_id": "CVE-2023-0001", "description": "Test CVE 1", "published_date": (datetime.now() - timedelta(days=1)).isoformat(), "vuln_status": "Analyzed"},
            {"cve_id": "CVE-2023-0002", "description": "Test CVE 2", "published_date": (datetime.now() - timedelta(days=2)).isoformat(), "vuln_status": "Analyzed"}
        ]
        self.cve_data_2 = [
            {"cve_id": "CVE-2023-0001", "description": "Duplicate CVE", "published_date": (datetime.now() - timedelta(days=3)).isoformat(), "vuln_status": "Analyzed"},
            {"cve_id": "CVE-2023-0003", "description": "Test CVE 3", "published_date": datetime.now().isoformat(), "vuln_status": "Analyzed"}
        ]

        with open(os.path.join(self.data_dir, "cves_1.json"), "w") as f:
            json.dump(self.cve_data_1, f)
        with open(os.path.join(self.data_dir, "cves_2.json"), "w") as f:
            json.dump(self.cve_data_2, f)

    def tearDown(self):
        """
        Clean up the test environment after each test.
        """
        for file in os.listdir(self.data_dir):
            os.remove(os.path.join(self.data_dir, file))
        os.rmdir(self.data_dir)

        if os.path.exists(self.reports_dir):
            for file in os.listdir(self.reports_dir):
                os.remove(os.path.join(self.reports_dir, file))
            os.rmdir(self.reports_dir)

    def test_generate_report(self):
        """
        Test the generate_report method.
        """
        generator = ReportGenerator(data_dir=self.data_dir, reports_dir=self.reports_dir)
        generator.generate_report()

        self.assertIsNotNone(generator.report_data)
        self.assertEqual(len(generator.report_data), 3)
        self.assertEqual(generator.report_data.iloc[0]["cve_id"], "CVE-2023-0003") # Newest
        self.assertEqual(generator.report_data.iloc[2]["cve_id"], "CVE-2023-0002") # Oldest

    def test_save_report(self):
        """
        Test the save_report method.
        """
        generator = ReportGenerator(data_dir=self.data_dir, reports_dir=self.reports_dir)
        generator.generate_report()
        generator.save_report()

        today_str = datetime.now().strftime('%Y-%m-%d')
        report_filename = os.path.join(self.reports_dir, f"Weekly_Threat_Report_{today_str}.md")

        self.assertTrue(os.path.exists(self.reports_dir))
        self.assertTrue(os.path.exists(report_filename))

        with open(report_filename, 'r') as f:
            content = f.read()
            self.assertIn("# Threat Intelligence Report", content)
            self.assertIn("CVE-2023-0001", content)
            self.assertIn("CVE-2023-0003", content)

if __name__ == "__main__":
    unittest.main()
