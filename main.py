from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from jinja2 import Environment, FileSystemLoader
from routers import finalExecute
from routers.failOver import failOver
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

# # New endpoint to filter rules by firewall
# @app.get("/filter_rules")
# async def filter_rules(firewall: str, type: str, db: Session = Depends(get_database)):
#     query = db.query(FirewallRule).filter(FirewallRule.final_status != "Completed")
#     if type == "src":
#         query = query.filter(FirewallRule.srcFirewall == firewall)
#     elif type == "dst":
#         query = query.filter(FirewallRule.firewall_hostname == firewall)  # Adjust if destination firewall is a different field
#     rules = query.all()
#     return JSONResponse({"rules": [rule.__dict__ for rule in rules]})



# Handle form submission
@app.post("/submit-rule")
async def submit_rule(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    srcFirewall_hostname = form_data.get("srcFirewall")
    dstFirewall_hostname = form_data.get("dstFirewall")
    interFirewall_hostname = form_data.get("interFirewall")#change row
    srcFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == srcFirewall_hostname).first()
    dstFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == dstFirewall_hostname).first()
    interFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == interFirewall_hostname).first() #change row
    if not srcFirewall and dstFirewall:
        raise HTTPException(status_code=404, detail="Either source firewall or destination firewall is wrong")
    srcFirewallIP = srcFirewall.ip
    
    dstFirewallIP = dstFirewall.ip
    
    interFirewallIP = interFirewall.ip
    # if not failOver(srcFirewallIP, username="your_user", password="your_pass", secret="your_secret"):
    #     raise HTTPException(status_code=500, detail=f"{srcFirewall_hostname} is not in ACTIVE state")
    # print(srcFirewallIP)
    # if not failOver(dstFirewallIP, username="your_user", password="your_pass", secret="your_secret"):
    #     raise HTTPException(status_code=500, detail=f"{dstFirewall_hostname} is not in ACTIVE state")
    
    # if not failOver(interFirewallIP, username="your_user", password="your_pass", secret="your_secret"):
    #     raise HTTPException(status_code=500, detail=f"{dstFirewall_hostname} is not in ACTIVE state")
    # Safely get and split IPs
 # Extract IPs properly by splitting on any whitespace
    from itertools import product

# Extract and clean source and destination IPs
    source_ips = [ip.strip() for ip in form_data.get("source_ip", "").split() if ip.strip()]
    dest_ips = [ip.strip() for ip in form_data.get("dest_ip", "").split() if ip.strip()]

    # Generate all permutations of source and destination IPs
    for index, (src_ip, dst_ip) in enumerate(product(source_ips, dest_ips)):
        new_rule = FirewallRule(
            itsr_number=form_data.get("itsr_number"),
            email=form_data.get("email"),
            source_ip=src_ip,
            dest_ip=dst_ip,
            inter_ip="",  # Leave intermediate IP empty
            multiple_ports=form_data.get("multiple_ports"),
            port_range_start=form_data.get("port_range_start"),
            port_range_end=form_data.get("port_range_end"),
            protocol=form_data.get("protocol"),
            ports=int(form_data.get("ports", 0)),
            srcFirewall=srcFirewall_hostname,
            dstFirewall=dstFirewall_hostname,
            interFirewall="",  # Leave intermediate firewall empty
            pre_status="Added to queue",
            post_status="Pending",
            final_status="Pending",
            created_by="admin",
            srcFirewallIP=srcFirewallIP,
            dstFirewallIP=dstFirewallIP,
            interFirewallIP=""
        )

        print(f"Entry {index + 1}")
        print(f"Source IP: {new_rule.source_ip}")
        print(f"Destination IP: {new_rule.dest_ip}")
        print("-" * 50)

        db.add(new_rule)

    db.commit()

    return {"message": "Source-Destination rules submitted successfully!"}


"""
src A b c
dst D E
         src    dst
row 1 -   A      D
row 2 -   b      E
row 3 -   c      Null
row 1     a     d
row 2     a     e
row 3     b     d
row 4     b     e
row 5     c     d
row 6     c     e
"""