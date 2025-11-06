from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

DATABASE_URL = "postgresql://postgres:patpimol00823@localhost:5432/esData"

engine = create_engine(DATABASE_URL, echo=True)  # echo=True to see SQL queries
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Rtarf(Base):
    __tablename__ = "rtarf_event"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)

    # Palo-XSIAM fields
    mitre_tactics_ids_and_names = Column(JSONB)
    mitre_techniques_ids_and_names = Column(JSONB)
    description = Column(String)
    severity = Column(String)
    alert_categories = Column(JSONB)

    # CrowdStrike fields
    crowdstrike_tactics = Column(JSONB)
    crowdstrike_tactics_ids = Column(JSONB)
    crowdstrike_techniques = Column(JSONB)
    crowdstrike_techniques_ids = Column(JSONB)
    crowdstrike_severity = Column(String(50))  # In db.py
    crowdstrike_event_name = Column(String)
    crowdstrike_event_objective = Column(String)
    
    # Suricata fields
    suricata_classification = Column(String)

    timestamp = Column(DateTime, default=datetime.utcnow)


# Create tables
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")


# Only create tables if this file is run directly
if __name__ == "__main__":
    print("Creating database tables...")
    init_db()