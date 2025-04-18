from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import paramiko

from database import get_db
from models import FirewallRule, FirewallList

router = APIRouter()

def push_command_to_firewall(ip: str, username: str, password: str, commands: list):
    # print("Trying to connect firewall")
    # print(f"Connecting to {ip}")
    # ssh = paramiko.SSHClient()
    # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ssh.connect(ip, username="vishal", password="#vishu1432")
    # for cmd in commands:
    #     print(ssh.exec_command(cmd))
    # ssh.close()
    pass

get_current_user = "admin"

@router.post("/final_execute")
def final_execute(db: Session = Depends(get_db), current_user = get_current_user):
    print("Entering final_execute from finalexecute.py")
  
    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.final_status == "Pending",
        FirewallRule.created_by == current_user
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules found for the current user.")

    completed_data = []
    print("Entering in for loop")
    for rule in pending_rules:
        # Check FirewallList for the firewall_hostname
        firewall_ip = db.query(FirewallList).filter(FirewallList.firewall_hostname == rule.firewall_hostname).first()
        ip_to_use = firewall_ip.ip if firewall_ip else "127.0.0.1"  # Default IP if not found

        # Print ID and IP if firewall_hostname exists in FirewallList
        if firewall_ip:
            print(f"Found firewall_hostname: {rule.firewall_hostname}, ID: {firewall_ip.id}, IP: {firewall_ip.ip}")
        else:
            print(f"Firewall_hostname: {rule.firewall_hostname} not found in FirewallList, using default IP: {ip_to_use}")

        commands = [f"ifconfig"]
        try:
            push_command_to_firewall(ip_to_use, "admin", "admin", commands)
            rule_data = {
                "model": "CISCO",
                "itsr_number": rule.itsr_number,
                "email": rule.email,
                "source_ip": rule.source_ip,
                "dest_ip": rule.dest_ip,
                "port_range_start": rule.port_range_start,
                "port_range_end": rule.port_range_end,
                "protocol": rule.protocol,
                "firewall_hostname": rule.firewall_hostname,
                "final_status": "Completed"
            }
            completed_data.append(rule_data)
            rule.final_status = "Completed"
            db.add(rule)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to push commands: {str(e)}")

    db.commit()

    if completed_data:
        print("Completed Rules Data:")
        for data in completed_data:
            print(data)
    else:
        print("No rules completed in this execution.")

    return {"message": "Commands executed and firewall rules updated.", "completed_data": completed_data}