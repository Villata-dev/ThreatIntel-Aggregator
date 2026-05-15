import os
from sqlalchemy import create_engine, Column, String, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the database URL
DB_URL = "sqlite:///data/threatintel.db"

# Create the engine
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our models
Base = declarative_base()

class Vulnerability(Base):
    """
    Model representing a CVE (Common Vulnerabilities and Exposures).
    """
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, index=True) # cve_id
    description = Column(Text)
    published_date = Column(DateTime)
    vuln_status = Column(String)
    cvss_score = Column(Float)

def init_db():
    """
    Initializes the database by creating all tables.
    """
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)

def get_db():
    """
    Returns a new database session.
    """
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()
