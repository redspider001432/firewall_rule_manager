from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException

# Assume these are defined elsewhere
from database import get_db
from models import FirewallRule, FirewallList

router = APIRouter()

def generate_asa_acl_commands(rule: FirewallRule) -> list:
    """
    Generate Cisco ASA ACL commands based on the firewall rule.
    Returns a list of commands or raises an error if required fields are missing.
    """
    # Validate required fields
    if not all([rule.protocol, rule.source_ip, rule.dest_ip, rule.src_subnet_mask, rule.dest_subnet_mask]):
        raise ValueError(f"Rule {rule.id} is missing required fields (protocol, source_ip, dest_ip, or masks)")

    commands = []
    base_cmd = f"access-list ITSR_ACL extended permit {rule.protocol.lower()} {rule.source_ip} {rule.src_subnet_mask} {rule.dest_ip} {rule.dest_subnet_mask}"

    # Handle port specifications for TCP/UDP
    if rule.protocol.lower() in ['tcp', 'udp']:
        if rule.port_range_start and rule.port_range_end:
            port_spec = f"range {rule.port_range_start} {rule.port_range_end}"
            commands.append(f"{base_cmd} {port_spec}")
        elif rule.multiple_ports:
            ports = rule.multiple_ports.split(',')
            for port in ports:
                if port.strip():
                    commands.append(f"{base_cmd} eq {port.strip()}")
        elif rule.ports and rule.ports != 0:
            commands.append(f"{base_cmd} eq {rule.ports}")
        else:
            commands.append(base_cmd)  # No specific ports, allow all
    else:
        commands.append(base_cmd)  # Non-TCP/UDP protocols (e.g., ICMP) don’t use ports

    return commands

def push_command_to_firewall(ip: str, username: str, password: str, commands: list):
    """Push commands to the Cisco ASA firewall via SSH using Netmiko."""
    if not ip:
        raise ValueError("Firewall IP is missing")

    device = {
        'device_type': 'cisco_asa',  # Specifically for Cisco ASA
        'ip': ip,
        'username': username,
        'password': password,
        'secret' : password
    }
    try:
        with ConnectHandler(**device) as net_connect:
            output = net_connect.send_config_set(commands)
            print(f"Commands pushed to {ip}: {output}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to push commands to {ip}: {str(e)}")

# Simulated current user (replace with actual authentication logic)
current_user = "admin"

@router.post("/final_execute")
def final_execute(db: Session = Depends(get_db), current_user: str = current_user):
    """
    Execute Cisco ASA ACL commands for all pending firewall rules created by the current user.
    - Filters rules where final_status is "Pending".
    - Generates and pushes ASA commands.
    - Updates rule status to "Completed" on success.
    """
    # Query pending rules for the current user
    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.final_status == "Pending",
        FirewallRule.created_by == current_user
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules found for the current user.")

    for rule in pending_rules:
        firewall_ip = db.query(FirewallList).filter(FirewallList.firewall_hostname == rule.firewall_hostname).first()
        ip_to_use = firewall_ip.ip if firewall_ip else "127.0.0.1"  # Default IP if not found
        if firewall_ip:
            print(f"Found firewall_hostname: {rule.firewall_hostname}, ID: {firewall_ip.id}, IP: {firewall_ip.ip}")
        else:
            print(f"Firewall_hostname: {rule.firewall_hostname} not found in FirewallList, using default IP: {ip_to_use}")
        try:
            # Generate ASA ACL commands
            commands = generate_asa_acl_commands(rule)
            # Push commands to the firewall
            push_command_to_firewall(ip_to_use, "admin", "admin", commands)
            # Update rule status to "Completed"
            rule.final_status = "Completed"
            db.add(rule)
        except ValueError as ve:
            # Skip invalid rules and log the issue
            print(f"Skipping rule {rule.id}: {str(ve)}")
            continue
        except HTTPException as he:
            raise he  # Re-raise connection/command errors
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to process rule {rule.id}: {str(e)}")

    db.commit()
    return {"message": "Commands executed and firewall rules updated successfully."}