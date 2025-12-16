import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import pandas as pd
from src.processors.report_generator import ReportGenerator
import os
import json

@pytest.fixture
def cve_data():
    """Fixture to create sample CVE data for testing."""
    return [
        {"cve_id": "CVE-2023-1234", "description": "Description 1", "published_date": "2023-01-01T00:00:00", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2023-5678", "description": "Description 2", "published_date": "2023-01-02T00:00:00", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2023-1234", "description": "Description 1", "published_date": "2023-01-01T00:00:00", "vuln_status": "Analyzed"}
    ]

@pytest.fixture
def temp_data_dir(tmp_path):
    """Fixture to create a temporary data directory for testing."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir

def test_deduplication(cve_data, temp_data_dir):
    """Tests that the ReportGenerator correctly removes duplicate CVEs."""
    # Save test data to a temporary file
    with open(temp_data_dir / "cves_test.json", "w") as f:
        json.dump(cve_data, f)

    # Initialize ReportGenerator with the temporary directory
    generator = ReportGenerator(data_dir=str(temp_data_dir))
    generator.generate_report()

    # Assert that duplicates are removed
    assert len(generator.report_data) == 2
    assert generator.report_data['cve_id'].nunique() == 2

def test_empty_data(temp_data_dir):
    """Tests that the ReportGenerator handles an empty data list without crashing."""
    # Create an empty CVE file
    with open(temp_data_dir / "cves_empty.json", "w") as f:
        json.dump([], f)

    generator = ReportGenerator(data_dir=str(temp_data_dir))
    generator.generate_report()

    # Assert that the report data is an empty DataFrame
    assert generator.report_data.empty

def test_markdown_structure(cve_data, temp_data_dir):
    """Tests that the output string contains key headers like '# Threat Intelligence Report'."""
    # Save test data to a temporary file
    with open(temp_data_dir / "cves_test.json", "w") as f:
        json.dump(cve_data, f)

    reports_dir = temp_data_dir / "reports"
    reports_dir.mkdir()

    generator = ReportGenerator(data_dir=str(temp_data_dir), reports_dir=str(reports_dir))
    generator.generate_report()
    generator.save_report()

    # Get the generated report file
    report_files = os.listdir(reports_dir)
    assert len(report_files) == 1
    report_file = reports_dir / report_files[0]

    with open(report_file, 'r') as f:
        content = f.read()

    assert "# Threat Intelligence Report" in content
    assert "## Executive Summary" in content
    assert "## Detailed CVE List" in content
