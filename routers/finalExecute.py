from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

from database import get_db
from models import FirewallRule, FirewallList

router = APIRouter()

def sanitize_email(email: str) -> str:
    """Sanitize email for use in object group names by replacing special characters."""
    return email.replace("@", "_").replace(".", "_")

def generate_asa_acl_commands(rule: FirewallRule) -> list:
    """
    Write your logic here to check interface of firewall and conectivity of ips  
    """

    """
    Generate Cisco ASA commands to create object groups and an ACL based on the firewall rule.
    Returns a list of commands or raises an error if required fields are missing.
    """
    # Validate required fields (ports optional for non-TCP/UDP protocols)
    if not all([rule.protocol, rule.source_ip, rule.dest_ip]):
        raise ValueError(f"Rule {rule.id} is missing required fields: protocol, source_ip, or dest_ip")

    # Sanitize email and create unique object group names
    sanitized_email = sanitize_email(rule.email)
    src_group = f"{rule.itsr_number}_{sanitized_email}_SRC"
    dest_group = f"{rule.itsr_number}_{sanitized_email}_DST"
    port_group = f"{rule.itsr_number}_{sanitized_email}_PORT"

    # Parse source and destination IPs (supporting commas or newlines)
    source_ips = [ip.strip() for ip in rule.source_ip.replace(",", "\n").split("\n") if ip.strip()]
    dest_ips = [ip.strip() for ip in rule.dest_ip.replace(",", "\n").split("\n") if ip.strip()]

    commands = []

    # Source network object group
    commands.append(f"object-group network {src_group}")
    for ip in source_ips:
        if "-" in ip:
            split_ip,subnet =ip.split("-")
            print()
            commands.append(f"network-object {split_ip} {subnet}")
        else:
            commands.append(f"network-object host {ip}")
        
    # Destination network object group
    commands.append(f"object-group network {dest_group}")
    for ip in dest_ips:
        if "-" in ip:
            split_ip,subnet =ip.split("-")
            commands.append(f"network-object {split_ip} {subnet}")
        else:
            commands.append(f"network-object host {ip}")
        # commands.append(f"network-object host {ip}")
    # Service object group for TCP/UDP with ports
    has_ports = bool(rule.multiple_ports or 
                     (rule.port_range_start and rule.port_range_end) or 
                     (rule.ports and rule.ports != 0))
    if rule.protocol.lower() in ['tcp', 'udp'] and has_ports:
        commands.append(f"object-group service {port_group} {rule.protocol.lower()}")
        if rule.multiple_ports:
            ports = [port.strip() for port in rule.multiple_ports.split(",") if port.strip()]
            for port in ports:
                commands.append(f"port-object eq {port}")
        if rule.port_range_start and rule.port_range_end:
            commands.append(f"port-object range {rule.port_range_start} {rule.port_range_end}")
        if rule.ports and rule.ports != 0:
            commands.append(f"port-object eq {rule.ports}")

    # Generate ACL command
    acl_cmd = f"access-list low_sec_nonlb_prod-ACL extended permit {rule.protocol.lower()} object-group {src_group} object-group {dest_group}"
    if rule.protocol.lower() in ['tcp', 'udp'] and has_ports:
        acl_cmd += f" object-group {port_group}"
        commands.append(acl_cmd)
    commands.append("wr")
    print("*"*100)
    print(commands)
    return commands

def push_command_to_firewall(ip: str, username: str, password: str, commands: list):
    """Push commands to the Cisco ASA firewall via SSH using Netmiko."""
    if not ip:
        raise ValueError("Firewall IP is missing")

    device = {
        'device_type': 'cisco_asa',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': password  # Enable secret for privileged mode
    }
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            output = net_connect.send_config_set(commands)
            print(f"Commands pushed to {ip}: {output}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to push commands to {ip}: {str(e)}")

@router.post("/final_execute")
def final_execute(db: Session = Depends(get_db), current_user: str = "admin"):
    """
    Execute Cisco ASA ACL commands for all pending firewall rules created by the current user.
    - Filters rules where final_status is "Pending".
    - Generates and pushes ASA commands using object groups.
    - Updates rule status to "Completed" on success.
    """
    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.final_status == "Pending",
        FirewallRule.created_by == current_user
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules found for the current user.")
    for rule in pending_rules:
        if rule.srcFirewall == rule.dstFirewall: # if both firewall hostnames are same we will use the same ip for both 
            firewall_ip = db.query(FirewallList).filter(FirewallList.firewall_hostname == rule.srcFirewall).first()
            ip_to_use = firewall_ip.ip if firewall_ip else "127.0.0.1"
            try:
                commands = generate_asa_acl_commands(rule)
                push_command_to_firewall(ip_to_use, "admin", "admin", commands)
                rule.final_status = "Completed"
                db.add(rule)
            except ValueError as ve:
                print(f"Skipping rule {rule.id}: {str(ve)}")
                continue
            except HTTPException as he:
                raise he
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to process rule {rule.id}: {str(e)}")
        elif rule.srcFirewall != rule.dstFirewall: # if not we have to pass both ips to push in firewalls 
            if rule.srcFirewall:
                src_firewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == rule.srcFirewall).first()
                dst_firewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == rule.dstFirewall).first()
                src_ip = src_firewall.ip
                dst_ip = dst_firewall.ip
                try:
                    commands = generate_asa_acl_commands(rule)
                    push_command_to_firewall(src_ip, "admin", "admin", commands)
                    push_command_to_firewall(dst_ip,"admin","admin",commands=commands)
                    rule.final_status = "Completed"
                    db.add(rule)
                except ValueError as ve:
                    print(f"Skipping rule {rule.id}: {str(ve)}")
                    continue
                except HTTPException as he:
                    print("Http exception occured final execute should be continued")
                except Exception as e:
                    print("Failed to push rule in firewall")                
    db.commit()
    return {"message": "Commands executed and firewall rules updated successfully."}