import os
import json
import unittest
from unittest.mock import patch, MagicMock
import pandas as pd
from datetime import datetime, timedelta
from src.processors.report_generator import ReportGenerator
from src.database.db_manager import SessionLocal, Vulnerability, Base, engine

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

        # Initialize DB and clear table
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.db.query(Vulnerability).delete()
        self.db.commit()

        # Create dummy CVE data
        self.cve_data = [
            Vulnerability(id="CVE-2023-0001", description="Test CVE 1", published_date=datetime.now() - timedelta(days=1), vuln_status="Analyzed", cvss_score=8.5),
            Vulnerability(id="CVE-2023-0002", description="Test CVE 2", published_date=datetime.now() - timedelta(days=2), vuln_status="Analyzed", cvss_score=5.0),
            Vulnerability(id="CVE-2023-0003", description="Test CVE 3", published_date=datetime.now(), vuln_status="Analyzed", cvss_score=None)
        ]
        for v in self.cve_data:
            self.db.add(v)
        self.db.commit()

    def tearDown(self):
        """
        Clean up the test environment after each test.
        """
        self.db.query(Vulnerability).delete()
        self.db.commit()
        self.db.close()

        if os.path.exists(self.data_dir):
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
            self.assertIn("High Priority Vulnerabilities", content)
            self.assertIn("CVE-2023-0001", content.split("High Priority Vulnerabilities")[1].split("Detailed CVE List")[0])
            self.assertNotIn("CVE-2023-0002", content.split("High Priority Vulnerabilities")[1].split("Detailed CVE List")[0])

    @patch('src.processors.report_generator.genai.GenerativeModel.generate_content')
    @patch('os.getenv')
    def test_generate_ai_summary_success(self, mock_getenv, mock_generate_content):
        """
        Test that generate_ai_summary correctly updates ai_summary using a mocked Gemini API.
        """
        # Configure os.getenv to return a fake API key
        mock_getenv.side_effect = lambda key: "fake_api_key" if key == "GEMINI_API_KEY" else os.environ.get(key)

        # Configure the mock for generate_content
        mock_response = MagicMock()
        mock_response.text = "Resumen simulado por IA"
        mock_generate_content.return_value = mock_response

        generator = ReportGenerator(data_dir=self.data_dir, reports_dir=self.reports_dir)
        generator.generate_report()
        generator.generate_ai_summary()

        self.assertEqual(generator.ai_summary, "Resumen simulado por IA")
        mock_generate_content.assert_called_once()

if __name__ == "__main__":
    unittest.main()
