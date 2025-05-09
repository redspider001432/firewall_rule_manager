from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList
from jinja2 import Environment, FileSystemLoader
from routers import finalExecute, checkInterface
from routers.failOver import failOver
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
    # Prepare firewall data with context names
    firewall_data = [
        {
            "firewall_hostname": fw.firewall_hostname,
            "context_names": [fw.context_name] if fw.context_name else []
        }
        for fw in firewalls
    ]
    return templates.get_template("index.html").render(
        request=request,
        rules=rules,
        firewalls=firewall_data
    )

# Handle form submission
@app.post("/submit-rule")
async def submit_rule(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    srcFirewall_display = form_data.get("srcFirewall")
    dstFirewall_display = form_data.get("dstFirewall")
    interFirewall_display = form_data.get("interFirewall")

    # Helper function to extract firewall_hostname and context_name
    def parse_firewall_value(display_value):
        if not display_value or display_value == "None":
            return None, None
        parts = display_value.split(":")
        hostname = parts[0]
        context = parts[1] if len(parts) > 1 else None
        return hostname, context

    # Extract firewall_hostname and context_name
    srcFirewall_hostname, srcContext = parse_firewall_value(srcFirewall_display)
    dstFirewall_hostname, dstContext = parse_firewall_value(dstFirewall_display)
    interFirewall_hostname, interContext = parse_firewall_value(interFirewall_display)

    # Query FirewallList using firewall_hostname
    srcFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == srcFirewall_hostname).first() if srcFirewall_hostname else None
    dstFirewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == dstFirewall_hostname).first() if dstFirewall_hostname else None
    
    if not srcFirewall and not dstFirewall:
        raise HTTPException(status_code=404, detail="Either source firewall or destination firewall is wrong")
    
    srcFirewallIP = srcFirewall.ip if srcFirewall else None
    dstFirewallIP = dstFirewall.ip if dstFirewall else None

    if srcFirewallIP:
        if not failOver(srcFirewallIP, username="amishra11", password="Dru56%Pty6", secret="Dru56%Pty6"):
            raise HTTPException(status_code=500, detail=f"{srcFirewall_hostname} is not in ACTIVE state")
    
    if dstFirewallIP:
        if not failOver(dstFirewallIP, username="amishra11", password="Dru56%Pty6", secret="Dru56%Pty6"):
            raise HTTPException(status_code=500, detail=f"{dstFirewall_hostname} is not in ACTIVE state")

    from itertools import product
    source_ips = [ip.strip() for ip in form_data.get("source_ip", "").split() if ip.strip()]
    dest_ips = [ip.strip() for ip in form_data.get("dest_ip", "").split() if ip.strip()]

    src_ip_list = source_ips or [None]
    dst_ip_list = dest_ips or [None]
    created_rule = []
    for index, (src_ip, dst_ip) in enumerate(product(src_ip_list, dst_ip_list)):
        new_rule = FirewallRule(
            itsr_number=form_data.get("itsr_number"),
            email=form_data.get("email"),
            source_ip=src_ip,
            dest_ip=dst_ip,
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
    
    db.flush()
    
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