# models.py
from sqlalchemy import Column, Integer, String, DateTime
from database import Base
import datetime


# Model for accessing it with ui

class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    itsr_number = Column(String(50), index=True)
    email = Column(String(100))
    source_ip = Column(String(50))
    src_subnet_mask = Column(String(50))
    dest_ip = Column(String(50))
    dest_subnet_mask = Column(String(50))
    protocol = Column(String(20))
    ports = Column(String(50))
    firewall_hostname = Column(String(100))
    pre_status = Column(String(50))
    post_status = Column(String(50))
    final_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
