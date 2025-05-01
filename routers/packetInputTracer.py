from database import get_db
from netmiko import ConnectHandler
from sqlalchemy.orm import Session
from database import FirewallRule  # Assuming this is your model file

def packetInputTracer(rule, src_firewall_ip, dst_firewall_ip ,username, password, secret,db: Session) -> list:
    """
    Generate Packet Tracer commands for firewall rules with 'pending' status and inLine != 'inline'.
    Returns a list of tuples: (firewall_ip, command, rule_id).
    """
    rule = db.query(FirewallRule).filter_by(source_ip=rule.source_ip, dest_ip=rule.dest_ip).first()
    if not rule:
        print(f"No rule found for src_ip={rule.source_ip} and dst_ip={rule.dest_ip}")
        return []

    # Determine protocol and ports
    protocol = rule.protocol.lower() if rule.protocol else "tcp"
    ports = rule.ports.split(",")[0].strip() if ports else "80"  # Use first port or default to 80

    # Generate Packet Tracer commands
    src_command = f"packet-tracer input {rule.src_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {ports}"
    dst_command = f"packet-tracer input {rule.src_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {ports}"  # Same interface since inLine == "inline"

    # Netmiko device configuration (assuming credentials are available in the calling context)
    # For this implementation, we'll assume credentials are passed or handled elsewhere
    # If needed, modify the function signature to include username, password, secret

    # Execute commands and collect results
    results = []
    try:
        # Source firewall
        src_device = {
            'device_type': 'cisco_asa',
            'ip': src_firewall_ip,
            'username': username,  # Placeholder; adjust as needed
            'password': password,  # Placeholder; adjust as needed
            'secret': secret  # Placeholder; adjust as needed
        }
        with ConnectHandler(**src_device) as conn:
            conn.enable()
            src_output = conn.send_command(src_command)
            src_action = parse_packet_tracer_output(src_output)
            results.append((src_firewall_ip, src_command, rule.id))

        # Destination firewall
        dst_device = {
            'device_type': 'cisco_asa',
            'ip': dst_firewall_ip,
            'username': username,  # Placeholder; adjust as needed
            'password': password,  # Placeholder; adjust as needed
            'secret': secret  # Placeholder; adjust as needed
        }
        with ConnectHandler(**dst_device) as conn:
            conn.enable()
            dst_output = conn.send_command(dst_command)
            dst_action = parse_packet_tracer_output(dst_output)
            results.append((dst_firewall_ip, dst_command, rule.id))

        # Determine overall status and update the rule
        status = "Allowed" if src_action == "allow" and dst_action == "allow" else "Dropped"
        print(f"Updated rule {rule.id} post_status to {status}")
        rule.Action = status
        db.commit()
        return status

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error executing Packet Tracer commands: {str(e)}")
        return results  # Return partial results if any

def parse_packet_tracer_output(output):
    """
    Parse the Packet Tracer output and extract the action from the last second line.
    """
    lines = output.strip().splitlines()
    if len(lines) >= 2:
        second_last_line = lines[-2].strip()
        if "Action:" in second_last_line:
            action = second_last_line.split("Action:")[1].strip()
            return action.lower()
    return "unknown"