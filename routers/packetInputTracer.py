from database import get_db
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from sqlalchemy.orm import Session
from models import FirewallRule  # Assuming this is your model file

def parse_packet_tracer_output(output):
    """
    Parse the Packet Tracer output to extract the action and reason.
    - For "allow" action, check if "permit" is in the output.
    - For "drop" action, capture the Drop-reason line.
    """
    lines = output.strip().splitlines()
    last_four_lines = lines[-4:] if len(lines) >= 4 else lines

    action = "unknown"
    reason = "unknown"

    # Search the last 4 lines for Action
    for line in last_four_lines:
        if "Action:" in line:
            action_part = line.split("Action:")[1].strip()
            action = action_part.lower()
            break  # Action found, no need to check further

    if action == "allow":
        # Search the entire output for "permit"
        for line in lines:
            if "permit" in line:
                reason = line
                break
    elif action == "drop":
        # Search the last 4 lines for Drop-reason
        for line in last_four_lines:
            if "Drop-reason:" in line:
                reason = line.strip()  # Capture the entire Drop-reason line
                break

    return action, reason

def packetInputTracer(rule, src_firewall_ip, dst_firewall_ip, username, password, secret, db: Session) -> list:
    """
    Generate Packet Tracer commands for firewall rules and set src_Action, dst_Action, src_Reason, dst_Reason.
    Returns a list of tuples: (firewall_ip, command, rule_id).
    """
    rule = db.query(FirewallRule).filter_by(source_ip=rule.source_ip, dest_ip=rule.dest_ip).first()
    if not rule:
        print(f"No rule found for src_ip={rule.source_ip} and dst_ip={rule.dest_ip}")
        return []

    # Determine protocol and ports
    protocol = rule.protocol.lower() if rule.protocol else "tcp"
    ports = rule.multiple_ports  # Use first port or default to 80

    # Generate Packet Tracer commands
    src_command = f"packet-tracer input {rule.src_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {ports}"
    dst_command = f"packet-tracer input {rule.dst_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {ports}"

    results = []
    try:
        # Source firewall
        src_device = {
            'device_type': 'cisco_asa',
            'ip': src_firewall_ip,
            'username': username,
            'password': password,
            'secret': secret
        }
        with ConnectHandler(**src_device) as conn:
            conn.enable()
            src_output = conn.send_command(src_command)
            src_action, src_reason = parse_packet_tracer_output(src_output)
            rule.src_Action = "Allowed" if src_action == "allow" else "Drop"
            rule.src_Reason = src_reason
            results.append((src_firewall_ip, src_command, rule.id))

        # Destination firewall
        dst_device = {
            'device_type': 'cisco_asa',
            'ip': dst_firewall_ip,
            'username': username,
            'password': password,
            'secret': secret
        }
        with ConnectHandler(**dst_device) as conn:
            conn.enable()
            dst_output = conn.send_command(dst_command)
            dst_action, dst_reason = parse_packet_tracer_output(dst_output)
            rule.dst_Action = "Allowed" if dst_action == "allow" else "Drop"
            rule.dst_Reason = dst_reason 
            results.append((dst_firewall_ip, dst_command, rule.id))

        print(f"Updated rule {rule.id}: src_Action={rule.src_Action}, src_Reason={rule.src_Reason}, dst_Action={rule.dst_Action}, dst_Reason={rule.dst_Reason}")
        db.commit()
        return results

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error executing Packet Tracer commands: {str(e)}")
        return results  