from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import FirewallRule
import paramiko

router = APIRouter()

def push_command_to_firewall(ip, user, password, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, password=password)
    for cmd in commands:
        ssh.exec_command(cmd)
    ssh.close()

@router.post("/final_execute/{itsr_number}")
def final_execute_by_itsr(itsr_number: str, db: Session = Depends(get_db)):
    # Step 1: Get all pending rules for this ITSR
    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.itsr_number == itsr_number,
        FirewallRule.final_status == "Pending"
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules for this ITSR")

    # Step 2: Execute commands in the firewall
    for rule in pending_rules:
        commands = [
            f"object-group network {rule.itsr_number}_SRC",
            f"network-object host {rule.source_ip}",
            f"object-group network {rule.itsr_number}_DST",
            f"network-object host {rule.dest_ip}",
            f"object-group service TCP-{rule.itsr_number} tcp",
            f"port-object eq {rule.ports}",
            f"access-list {rule.itsr_number} extended permit {rule.protocol} object-group {rule.itsr_number}_SRC object-group {rule.itsr_number}_DST object-group TCP-{rule.itsr_number}"
        ]

        try:
            push_command_to_firewall(rule.firewall_hostname, "fwadmin", "secret", commands)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to push commands: {str(e)}")

    # Step 3: Delete all rules for this ITSR
    db.query(FirewallRule).filter(FirewallRule.itsr_number == itsr_number).delete()
    db.commit()

    return {"message": f"Commands executed and rules for ITSR {itsr_number} deleted."}