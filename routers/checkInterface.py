from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from models import FirewallRule  # Adjust based on your actual imports
import re 
from routers.packetInputTracer import *

def extract_interface(route_output):
    """Extract the interface name from the 'show route' command output."""
    # Example output: "Route to 192.168.1.10 via GigabitEthernet0/1"
    candidates = re.findall(r'via\s+([^\s,()]+)', route_output)
    interfaces = [i for i in candidates if i.lower() != 'interface']
    interface =  interfaces[-1] if interfaces else None
    print(interface)
    return interface

def extract_default_interface(firewall_ip, username, password, secret):
    print(f"For default interface {firewall_ip},{username},{password} , {secret}")
    """Extract the interface for a given IP from a firewall."""
    device = {
        'device_type': 'cisco_asa',
        'ip': firewall_ip,
        'username': username,
        'password': password,
        'secret': secret
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            output = conn.send_command(f"show route")
            print("*"*50)
            print(output.splitlines())
            print("*"*50)
            for line in output.splitlines():
                if "S*" in line:
                    print(line.split(",")[-1].strip())
                    return line.split(",")[-1].strip()
    except:
        print("Wasnt able to connect firewall for default interface 33")
def extract_interface_for_ip(firewall_ip, username, password, secret, ip):
    """Extract the interface for a given IP from a firewall."""
    device = {
        'device_type': 'cisco_asa',
        'ip': firewall_ip,
        'username': username,
        'password': password,
        'secret': secret
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            output = conn.send_command(f"show route {ip}")
            interface = extract_interface(output)
            if interface:
                return interface
            else:
                print(f"No route found for IP {ip} on firewall {firewall_ip}")
                return None
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error connecting to firewall {firewall_ip}: {str(e)}")
        return None
def update_firewall_interfaces_for_rule(src_firewall_ip, dst_firewall_ip, src_ip, dst_ip, username, password, secret, db):
    """Update src_interface and dst_interface for a specific rule based on src_ip and dst_ip."""
    try:
        # Find the rule that matches the provided src_ip and dst_ip
        rule = db.query(FirewallRule).filter_by(source_ip=src_ip, dest_ip=dst_ip).first()
        if not rule:
            print(f"No rule found for src_ip={src_ip} and dst_ip={dst_ip}")

        # Check if the firewall IPs match the rule's firewall IPs
        if rule.srcFirewallIP != src_firewall_ip or rule.dstFirewallIP != dst_firewall_ip:
            print(f"Firewall IP mismatch for rule {rule.id}")
        # Extract interface for source IP from source firewall
        src_interface = extract_interface_for_ip(
            firewall_ip=src_firewall_ip,
            username=username,
            password=password,
            secret=secret,
            ip=src_ip
        )
        print(f"{src_interface} after extracting it from firewall")
        # Extract interface for destination IP from destination firewall
        dst_interface = extract_interface_for_ip(
            firewall_ip=dst_firewall_ip,
            username=username,
            password=password,
            secret=secret,
            ip=dst_ip
        )
        print(f"{dst_interface} after extracting it from firewall")
        if (src_interface is None and dst_interface is not None) or (src_interface is not None and dst_interface is None): 
            if src_interface is None: 
                src_interface = extract_default_interface(firewall_ip=src_firewall_ip, username=username, password=password, secret=secret)
                print("*"*200,src_interface)
            if dst_interface is None:
                dst_interface = extract_default_interface(firewall_ip=dst_firewall_ip, username=username, password=password, secret=secret)
                print("*"*200,dst_interface) 
        else:
            if src_interface is None and dst_interface is None:
                rule.pre_status = "No route available"
                rule.post_status= "No route available"
                db.commit()
                return None
        if src_interface or dst_interface:
            if src_interface == dst_interface:
                rule.inLine = "not inline"
            else: 
                rule.inLine = "inline"
                db.flush()
                status = packetInputTracer(
                    rule=rule,
                    src_firewall_ip=src_firewall_ip,
                    dst_firewall_ip=dst_firewall_ip,
                    username=username,
                    password=password,
                    db=db
                )
                print("*"*50,status)
            rule.src_interface = src_interface
            rule.dst_interface = dst_interface
            db.commit()
            print(f"Updated rule {rule.id}: src_interface={src_interface}, dst_interface={dst_interface}")
        else:
            print(f"Failed to update rule {rule.id}: Could not extract one or both interfaces")

    except Exception as e:
        print(f"Error processing rule for src_ip={src_ip}, dst_ip={dst_ip}: {str(e)}")
        db.rollback()
