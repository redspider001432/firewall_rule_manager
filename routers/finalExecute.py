from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import paramiko

# Assume get_db and get_current_user are defined elsewhere
from database import get_db
from models import FirewallRule

router = APIRouter()

def push_command_to_firewall(ip: str, username: str, password: str, commands: list):
    """Push commands to the firewall via SSH."""
    print("Trying to connect firewall")
    print("username")
    print(f"{ip}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("127.0.0.1", username="vishal", password="#vishu1432")
    for cmd in commands:
        print(ssh.exec_command(cmd))
    ssh.close()
get_current_user = "admin"
@router.post("/final_execute")
def final_execute(
    db: Session = Depends(get_db),
    current_user = get_current_user
):
    """
    For the current user, the endpoint:
    1. Queries all pending firewall rules.
    2. Pushes the required commands to the firewall.
    3. Updates the status of each rule upon success.
    """
    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.final_status == "Pending",
        FirewallRule.created_by == current_user
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules found for the current user.")

    for rule in pending_rules:
        # Build the command list for the rule.
        # Replace the example command with your actual command logic.
        commands = [f"ifconfig"]
        try:
            push_command_to_firewall(rule.firewall_hostname, "admin", "admin", commands)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to push commands: {str(e)}")

        # Update the firewall rule status after successful command execution.
        rule.final_status = "Completed"
        db.add(rule)

    db.commit()
    return {"message": "Commands executed and firewall rules updated."}
