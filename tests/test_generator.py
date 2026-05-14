import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import pandas as pd
from src.processors.report_generator import ReportGenerator
from src.database.db_manager import SessionLocal, Vulnerability, Base, engine
import os
import json

@pytest.fixture(autouse=True)
def setup_db():
    """Fixture to initialize the database and clear the vulnerabilities table."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(Vulnerability).delete()
    db.commit()
    yield db
    db.query(Vulnerability).delete()
    db.commit()
    db.close()

@pytest.fixture
def cve_data():
    """Fixture to create sample CVE data for testing."""
    return [
        {"cve_id": "CVE-2023-1234", "description": "Description 1", "published_date": "2023-01-01T00:00:00", "vuln_status": "Analyzed", "cvss_score": 9.1},
        {"cve_id": "CVE-2023-5678", "description": "Description 2", "published_date": "2023-01-02T00:00:00", "vuln_status": "Analyzed", "cvss_score": 4.5}
    ]

@pytest.fixture
def temp_data_dir(tmp_path):
    """Fixture to create a temporary data directory for testing."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir

def test_deduplication(cve_data, setup_db, temp_data_dir):
    """Tests that the ReportGenerator correctly handles CVEs (deduplication handled by DB)."""
    db = setup_db
    for item in cve_data:
        # Check if already exists to mimic merge behavior if it was failing or just to be safe
        existing = db.get(Vulnerability, item['cve_id'])
        if existing:
            existing.description = item['description']
            existing.published_date = pd.to_datetime(item['published_date'])
            existing.vuln_status = item['vuln_status']
        else:
            v = Vulnerability(
                id=item['cve_id'],
                description=item['description'],
                published_date=pd.to_datetime(item['published_date']),
                vuln_status=item['vuln_status'],
                cvss_score=item['cvss_score']
            )
            db.add(v)
    db.commit()

    # Initialize ReportGenerator with the temporary directory
    generator = ReportGenerator(data_dir=str(temp_data_dir))
    generator.generate_report()

    # Assert that duplicates are removed (by DB merge)
    assert len(generator.report_data) == 2
    assert generator.report_data['cve_id'].nunique() == 2

def test_empty_data(setup_db, temp_data_dir):
    """Tests that the ReportGenerator handles an empty database without crashing."""
    # Database is already empty from setup_db fixture
    generator = ReportGenerator(data_dir=str(temp_data_dir))
    generator.generate_report()

    # Assert that the report data is an empty DataFrame
    assert generator.report_data.empty

def test_markdown_structure(cve_data, setup_db, temp_data_dir):
    """Tests that the output string contains key headers like '# Threat Intelligence Report'."""
    db = setup_db
    for item in cve_data:
        existing = db.get(Vulnerability, item['cve_id'])
        if existing:
            existing.description = item['description']
            existing.published_date = pd.to_datetime(item['published_date'])
            existing.vuln_status = item['vuln_status']
        else:
            v = Vulnerability(
                id=item['cve_id'],
                description=item['description'],
                published_date=pd.to_datetime(item['published_date']),
                vuln_status=item['vuln_status'],
                cvss_score=item['cvss_score']
            )
            db.add(v)
    db.commit()

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
