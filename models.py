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
    source_ip = Column(Text)
    dest_ip = Column(Text)
    src_interface=Column(Text)
    dst_interface =Column(Text)
    multiple_ports = Column(String(50))
    port_range_start = Column(Text, nullable=False)
    port_range_end = Column(Text, nullable=False)
    protocol = Column(String(20))
    ports = Column(String(5000))
    pre_status = Column(String(50))
    post_status = Column(String(50))
    final_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(String(20))
    # Set firewall_hostname as a foreign key referencing firewall_list.firewall_hostname
    srcFirewall = Column(String(100))
    dstFirewall = Column(String(100))
    srcFirewallIP = Column(String(100))
    dstFirewallIP = Column(String(100))
    interFirewall = Column(String(100))
    inLine = Column(String(100))
    src_Action = Column(String(10))
    dst_Action = Column(String(10))
    src_Reason = Column(Text)
    dst_Reason = Column(Text)
    
class FirewallList(Base):
    __tablename__ = "firewall_list"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(20))
    firewall_hostname = Column(String(100))
    model = Column(String(20))
    context_name = Column(String(20))

