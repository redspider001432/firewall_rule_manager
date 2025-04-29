from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from jinja2 import Environment, FileSystemLoader
from routers import finalExecute, failOver, checkInterface
app = FastAPI()

# Set up Jinja2 environment
templates = Environment(loader=FileSystemLoader("templates"))
app.include_router(finalExecute.router)

FirewallList.__table__.create(bind=engine, checkfirst=True)
FirewallRule.__table__.create(bind=engine, checkfirst=True)
# Dependency to get DB session
def get_database():
    yield from get_db()


# Route to render the HTML page with filtered rules
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_database)):
    rules = db.query(FirewallRule).filter(FirewallRule.final_status != "Completed").all()
    firewalls = db.query(FirewallList).all()
    return templates.get_template("index.html").render(
        request=request,
        rules=rules,
        firewalls=firewalls
    )

# Handle form submission
@app.post("/submit-rule")
async def submit_rule(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    srcFirewall_hostname = form_data.get("srcFirewall")
    dstFirewall_hostname = form_data.get("dstFirewall")
    interFirewall_hostname = form_data.get("interFirewall")#change row
    srcFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == srcFirewall_hostname).first()
    dstFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == dstFirewall_hostname).first()
    if not srcFirewall and not dstFirewall:
        raise HTTPException(status_code=404, detail="Either source firewall or destination firewall is wrong")
    srcFirewallIP = srcFirewall.ip
    dstFirewallIP = dstFirewall.ip

    if not failOver(srcFirewallIP, username="amishra11", password="Dru56%Pty6", secret="Dru56%Pty6"):
        raise HTTPException(status_code=500, detail=f"{srcFirewall_hostname} is not in ACTIVE state")
    print(srcFirewallIP)
    if not failOver(dstFirewallIP, username="amishra11", password="Dru56%Pty6", secret="Dru56%Pty6"):
        raise HTTPException(status_code=500, detail=f"{dstFirewall_hostname} is not in ACTIVE state")
 # Extract IPs properly by splitting on any whitespace
    from itertools import product

# Extract and clean source and destination IPs
    source_ips = [ip.strip() for ip in form_data.get("source_ip", "").split() if ip.strip()]
    dest_ips = [ip.strip() for ip in form_data.get("dest_ip", "").split() if ip.strip()]

    # Generate all permutations of source and destination IPs
    created_rule = []
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
            interFirewall=interFirewall_hostname,
            pre_status="Added to queue",
            post_status="Pending",
            final_status="Pending",
            created_by="admin",
            srcFirewallIP=srcFirewallIP,
            dstFirewallIP=dstFirewallIP,
        )

        print(f"Entry {index + 1}")
        print(f"Source IP: {new_rule.source_ip}")
        print(f"Destination IP: {new_rule.dest_ip}")
        print("-" * 50)

        db.add(new_rule)
        created_rule.append(new_rule)


    for rule in created_rule:
        checkInterface.update_firewall_interfaces_for_rule(
            src_firewall_ip=rule.srcFirewallIP,
            dst_firewall_ip=rule.dstFirewallIP,
            src_ip=rule.source_ip,
            dst_ip=rule.dest_ip,
            username="amishra11",
            password="Dru56%Pty6",
            secret="Dru56%Pty6",
            db=db
        )
    db.commit()
    return {"message": "Source-Destination rules submitted successfully!"}


    