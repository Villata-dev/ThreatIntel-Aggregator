import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import pandas as pd
from src.processors.report_generator import ReportGenerator
from src.database.db_manager import SessionLocal, Vulnerability, Base, engine
import json
from unittest.mock import patch

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
        {"cve_id": "CVE-2023-PYTHON", "description": "A vulnerability in Python applications.", "published_date": "2023-01-01T00:00:00", "vuln_status": "Analyzed", "cvss_score": 9.1},
        {"cve_id": "CVE-2023-LINUX", "description": "A kernel issue in Linux systems.", "published_date": "2023-01-02T00:00:00", "vuln_status": "Analyzed", "cvss_score": 4.5},
        {"cve_id": "CVE-2023-WINDOWS", "description": "An exploit in Windows Server.", "published_date": "2023-01-03T00:00:00", "vuln_status": "Analyzed", "cvss_score": 7.5}
    ]

@pytest.fixture
def temp_data_dir(tmp_path):
    """Fixture to create a temporary data directory for testing."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir

def test_cve_keyword_filtering(cve_data, setup_db, temp_data_dir):
    """Tests that CVEs are correctly filtered by keywords."""
    db = setup_db
    for item in cve_data:
        v = Vulnerability(
            id=item['cve_id'],
            description=item['description'],
            published_date=pd.to_datetime(item['published_date']),
            vuln_status=item['vuln_status'],
            cvss_score=item['cvss_score']
        )
        db.add(v)
    db.commit()

    # Set keywords in environment
    with patch.dict(os.environ, {"TARGET_KEYWORDS": "python, linux"}):
        generator = ReportGenerator(data_dir=str(temp_data_dir))
        generator.generate_report()

    # Should only contain Python and Linux CVEs
    assert len(generator.report_data) == 2
    assert "CVE-2023-PYTHON" in generator.report_data['cve_id'].values
    assert "CVE-2023-LINUX" in generator.report_data['cve_id'].values
    assert "CVE-2023-WINDOWS" not in generator.report_data['cve_id'].values

def test_news_keyword_filtering(temp_data_dir):
    """Tests that news articles are correctly filtered by keywords."""
    news_content = {
        "Source 1": [
            {"title": "New Python vulnerability found", "link": "http://example.com/1"},
            {"title": "Windows update released", "link": "http://example.com/2"}
        ],
        "Source 2": [
            {"title": "Linux kernel patch", "link": "http://example.com/3"}
        ]
    }

    news_file = temp_data_dir / "news_20230101.json"
    with open(news_file, 'w') as f:
        json.dump(news_content, f)

    # Set keywords in environment
    with patch.dict(os.environ, {"TARGET_KEYWORDS": "python, linux"}):
        generator = ReportGenerator(data_dir=str(temp_data_dir))
        generator.generate_report()

    # Should only contain Python and Linux news
    assert "Source 1" in generator.news_data
    assert len(generator.news_data["Source 1"]) == 1
    assert generator.news_data["Source 1"][0]["title"] == "New Python vulnerability found"

    assert "Source 2" in generator.news_data
    assert len(generator.news_data["Source 2"]) == 1
    assert generator.news_data["Source 2"][0]["title"] == "Linux kernel patch"

def test_no_keywords_filtering(cve_data, setup_db, temp_data_dir):
    """Tests that no filtering occurs if TARGET_KEYWORDS is empty."""
    db = setup_db
    for item in cve_data:
        v = Vulnerability(
            id=item['cve_id'],
            description=item['description'],
            published_date=pd.to_datetime(item['published_date']),
            vuln_status=item['vuln_status'],
            cvss_score=item['cvss_score']
        )
        db.add(v)
    db.commit()

    with patch.dict(os.environ, {"TARGET_KEYWORDS": ""}):
        generator = ReportGenerator(data_dir=str(temp_data_dir))
        generator.generate_report()

    assert len(generator.report_data) == 3

def test_gemini_prompt_with_keywords(cve_data, setup_db, temp_data_dir):
    """Tests that the Gemini prompt includes the keywords."""
    db = setup_db
    v = Vulnerability(
        id=cve_data[0]['cve_id'],
        description=cve_data[0]['description'],
        published_date=pd.to_datetime(cve_data[0]['published_date']),
        vuln_status=cve_data[0]['vuln_status'],
        cvss_score=cve_data[0]['cvss_score']
    )
    db.add(v)
    db.commit()

    with patch.dict(os.environ, {"TARGET_KEYWORDS": "python", "GEMINI_API_KEY": "fake_key"}):
        generator = ReportGenerator(data_dir=str(temp_data_dir))
        generator.generate_report()

        with patch('src.processors.report_generator.genai.GenerativeModel') as mock_model:
            generator.generate_ai_summary()

            # Check if generate_content was called with a prompt containing 'python'
            args, kwargs = mock_model.return_value.generate_content.call_args
            prompt = args[0]
            assert "presta especial atención a las siguientes palabras clave o tecnologías: python" in prompt
