from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from jinja2 import Environment, FileSystemLoader

app = FastAPI()

# Set up Jinja2 environment
templates = Environment(loader=FileSystemLoader("templates"))
FirewallList._table_.create(bind=engine, checkfirst=True)
FirewallRule._table_.create(bind=engine, checkfirst=True)
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
        pre_status="Added to queue",
        post_status="Pending",
        final_status="Pending"
    )
    db.add(new_rule)
    db.commit()
    return {"message": "Rule submitted!"}

# Final execute route
@app.post("/final_execute")
async def final_execute(db: Session = Depends(get_database)):
    db.query(FirewallRule).filter(FirewallRule.final_status == "Pending").update({"final_status": "Completed"})
    db.commit()
    return {"message": "Execution completed, statuses updated!"}

# Create tables
def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)