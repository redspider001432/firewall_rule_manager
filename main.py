from fastapi import FastAPI, Depends, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from database import engine, get_db
from starlette.requests import Request
import os
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
    request: Request,
    itsr_number: str = Form(...),
    email: str = Form(...),
    source_ip: str = Form(...),
    src_subnet_mask: str = Form(...),
    dest_ip: str = Form(...),
    dest_subnet_mask: str = Form(...),
    multiple_ports: str = Form(...),
    port_range_start: str = Form(...),
    port_range_end: str = Form(...),
    protocol: str = Form(...),
    ports: int = Form(...),
    firewall_hostname: str = Form(...),
    pre_status: str = Form(...),
    post_status: str = Form(...),
    final_status: str = Form(...),
    db: Session = Depends(get_database)
):
    new_rule = FirewallRule(
        itsr_number=itsr_number,
        email=email,
        source_ip=source_ip,
        src_subnet_mask=src_subnet_mask,
        dest_ip=dest_ip,
        dest_subnet_mask=dest_subnet_mask,
        multiple_ports=multiple_ports,
        port_range_start=port_range_start,
        port_range_end=port_range_end,
        protocol=protocol,
        ports=ports,
        firewall_hostname=firewall_hostname,
        pre_status=pre_status,
        post_status=post_status,
        final_status=final_status,
        created_by=user
    )
   
    db.add(new_rule)
    db.commit()
    
        
    return {"message": "Rule added successfully"}

# Updated index.html to handle form submission and display dynamic data