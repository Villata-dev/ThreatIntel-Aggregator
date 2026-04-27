import os
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# Use environment variable for database URL or default to production
DB_URL = os.getenv("DATABASE_URL", "sqlite:///data/threatintel.db")

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

def init_db():
    """
    Initializes the database by creating all tables.
    """
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)

def get_db():
    """
    Generator that provides a database session and ensures it's closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
