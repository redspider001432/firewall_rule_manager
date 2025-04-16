from typing import Optional
from fastapi import FastAPI, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList, StatusEnum
from database import engine, get_db
from starlette.requests import Request
import os
from pydantic import BaseModel, IPv4Address, EmailStr, conint
from dotenv import load_dotenv
from routers import finalExecute
load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.include_router(finalExecute.router)

# Create tables (if not already created)
FirewallList.__table__.create(bind=engine, checkfirst=True)
FirewallRule.__table__.create(bind=engine, checkfirst=True)

#Dependency to get DB session
def get_database():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()

class FirewallRuleCreate(BaseModel):
    itsr_number: str
    email: EmailStr
    source_ip: IPv4Address
    src_subnet_mask: str
    dest_ip: IPv4Address
    dest_subnet_mask: str
    multiple_ports: Optional[str] = None
    port_range_start: str
    port_range_end: str
    protocol: str
    ports: conint(ge=0, le=65536) # Validate port range
    firewall_id: int  # Updated to use firewall_id
    pre_status: StatusEnum = StatusEnum.PENDING
    post_status: StatusEnum = StatusEnum.PENDING
    final_status: StatusEnum = StatusEnum.PENDING

# Render the main page with firewall rules
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_database)):
    rules = db.query(FirewallRule).all()
    firewalls = db.query(FirewallList).all()
    return templates.TemplateResponse("index.html", {"request": request, "rules": rules, "firewalls": firewalls})

# Handle form submission to add a new rule
user= "admin"
password = "admin"
@app.post("/submit-rule")
async def submit_rule(
    rule: FirewallRuleCreate,
    db: Session = Depends(get_database),
    current_user = "admin"
    #current_user: str = Depends(finalExecute.get_current_user)
):
    firewall = db.query(FirewallList).filter(FirewallList.id == rule.firewall_id).first()
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found in FirewallList")
    new_rule = FirewallRule(
        itsr_number=rule.itsr_number,
        email=rule.email,
        source_ip=str(rule.source_ip),
        src_subnet_mask=rule.src_subnet_mask,
        dest_ip=str(rule.dest_ip),
        dest_subnet_mask=rule.dest_subnet_mask,
        multiple_ports=rule.multiple_ports,
        port_range_start=rule.port_range_start,
        port_range_end=rule.port_range_end,
        protocol=rule.protocol,
        ports=rule.ports,
        firewall_id=rule.firewall_id,  
        pre_status=rule.pre_status,
        post_status=rule.post_status,
        final_status=rule.final_status,
        created_by=current_user
    )
   
    db.add(new_rule)
    db.commit()
    
        
    return {"message": "Rule added successfully"}

