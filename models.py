from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from database import Base
import datetime
from sqlalchemy.orm import relationship

# Model for accessing it with UI
class FirewallRule(Base):
    __tablename__ = "itsr_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    itsr_number = Column(String(50), index=True)
    email = Column(String(100))
    source_ip = Column(String(50))
    src_subnet_mask = Column(String(50))
    dest_ip = Column(String(50))
    dest_subnet_mask = Column(String(50))
    multiple_ports = Column(String(50))
    port_range_start = Column(Text, nullable=False)
    port_range_end = Column(Text, nullable=False)
    protocol = Column(String(20))
    ports = Column(Integer)
    pre_status = Column(String(50))
    post_status = Column(String(50))
    final_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(String(20))
    # Set firewall_hostname as a foreign key referencing firewall_list.firewall_hostname
    firewall_hostname = Column(String(100), ForeignKey("firewall_list.firewall_hostname"))
    # Optional: Create a relationship to easily access firewall data from a rule
    firewall = relationship("FirewallList", back_populates="rules")

class FirewallList(Base):
    __tablename__ = "firewall_list"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(20))
    firewall_hostname = Column(String(100),unique=True)
    model = Column(String(20))
    context_name = Column(String(20))

    # Optional: Reverse relationship to get a list of rules associated with this firewall
    rules = relationship("FirewallRule", back_populates="firewall")