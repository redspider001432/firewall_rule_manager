from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from jinja2 import Environment, FileSystemLoader
from routers import finalExecute
app = FastAPI()

# Set up Jinja2 environment
templates = Environment(loader=FileSystemLoader("templates"))
app.include_router(finalExecute.router)

FirewallList.__table__.create(bind=engine, checkfirst=True)
FirewallRule.__table__.create(bind=engine, checkfirst=True)
# Dependency to get DB session
def get_database():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


# Route to render the HTML page with filtered rules
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_database)):
    rules = db.query(FirewallRule).filter(FirewallRule.final_status != "Completed").all()
    firewalls = db.query(FirewallList).all()
    return templates.get_template("index"
    ".html").render(
        request=request,
        rules=rules,
        firewalls=firewalls
    )

# New endpoint to filter rules by firewall
@app.get("/filter_rules")
async def filter_rules(firewall: str, type: str, db: Session = Depends(get_database)):
    query = db.query(FirewallRule).filter(FirewallRule.final_status != "Completed")
    if type == "src":
        query = query.filter(FirewallRule.firewall_hostname == firewall)
    elif type == "dst":
        query = query.filter(FirewallRule.firewall_hostname == firewall)  # Adjust if destination firewall is a different field
    rules = query.all()
    return JSONResponse({"rules": [rule.__dict__ for rule in rules]})



# Handle form submission
@app.post("/submit-rule")
async def submit_rule(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    firewall_hostname = form_data.get("firewall_hostname")
    firewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == firewall_hostname).first()
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found in FirewallList")
    firewall_ip = firewall.ip
    new_rule = FirewallRule(
        itsr_number=form_data.get("itsr_number"),
        email=form_data.get("email"),
        source_ip=form_data.get("source_ip"),
        src_subnet_mask=form_data.get("src_subnet_mask"),
        dest_ip=form_data.get("dest_ip"),
        dest_subnet_mask=form_data.get("dest_subnet_mask"),
        multiple_ports=form_data.get("multiple_ports"),
        port_range_start=form_data.get("port_range_start"),
        port_range_end=form_data.get("port_range_end"),
        protocol=form_data.get("protocol"),
        ports=int(form_data.get("ports", 0)),
        firewall_hostname=form_data.get("firewall_hostname", "blr-vpn-fw01:0"),
        firewall_ip = firewall_ip,
        pre_status="Added to queue",
        post_status="Pending",
        final_status="Pending",
        created_by = "admin"
    )
    db.add(new_rule)
    db.commit()
    return {"message": "Rule submitted!"}

