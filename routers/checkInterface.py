from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from database import get_db, Base, engine
from models import FirewallRule


def get_database():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


def extract_ip(ip_spec):
    """Extract the IP part before the hyphen, if present."""
    return ip_spec.split('-')[0] if '-' in ip_spec else ip_spec

# Function to extract outgoing interface from 'show route' output
def extract_interface(output):
    """Extract the outgoing interface from the 'show route' output."""
    lines = output.splitlines()
    for line in lines:
        if line.strip().startswith("*") and "via" in line:
            return line.split("via")[-1].strip()
    return None

# Modified function to check routes across firewalls
def check_routes_across_firewalls(src_firewall_ip, dst_firewall_ip, username, password, secret, src_ips, dst_ips):
    """Check routes and return pairs with matching interfaces."""
    if not src_firewall_ip or not dst_firewall_ip:
        print("Error: Firewall IP missing")
        return []

    src_device = {
        'device_type': 'cisco_asa',
        'ip': src_firewall_ip,
        'username': username,
        'password': password,
        'secret': secret
    }
    dst_device = {
        'device_type': 'cisco_asa',
        'ip': dst_firewall_ip,
        'username': username,
        'password': password,
        'secret': secret
    }

    src_interfaces = {}
    try:
        with ConnectHandler(**src_device) as src_conn:
            src_conn.enable()
            for src_ip in src_ips:
                ip_only = extract_ip(src_ip)
                output = src_conn.send_command(f"show route {ip_only}")
                interface = extract_interface(output)
                if interface:
                    src_interfaces[ip_only] = interface
                else:
                    print(f"No route found for {ip_only} on source firewall {src_firewall_ip}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error connecting to source firewall {src_firewall_ip}: {str(e)}")
        return []

    dst_interfaces = {}
    try:
        with ConnectHandler(**dst_device) as dst_conn:
            dst_conn.enable()
            for dst_ip in dst_ips:
                ip_only = extract_ip(dst_ip)
                output = dst_conn.send_command(f"show route {ip_only}")
                interface = extract_interface(output)
                if interface:
                    dst_interfaces[ip_only] = interface
                else:
                    print(f"No route found for {ip_only} on destination firewall {dst_firewall_ip}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error connecting to destination firewall {dst_firewall_ip}: {str(e)}")
        return []

    matching_pairs = []
    for src_ip, src_intf in src_interfaces.items():
        for dst_ip, dst_intf in dst_interfaces.items():
            if src_intf == dst_intf:
                matching_pairs.append((src_ip, dst_ip, src_intf))

    return matching_pairs

# Main function to update inLine status
def update_inline_status():
    db = next(get_db())
    try:
        # Retrieve all firewall rules
        rules = db.query(FirewallRule).all()

        # Firewall credentials (replace with secure method in production)
        username = "admin"  # Replace with actual username
        password = "cisco"  # Replace with actual password
        secret = "cisco"    # Replace with actual secret

        for rule in rules:
            # Skip rules with missing firewall IPs
            if not rule.srcFirewallIP or not rule.dstFirewallIP:
                print(f"Skipping rule {rule.id}: Missing firewall IP")
                continue

            # Parse source and destination IPs (handle comma-separated lists)
            src_ips = [ip.strip() for ip in rule.source_ip.split(',')] if rule.source_ip else []
            dst_ips = [ip.strip() for ip in rule.dest_ip.split(',')] if rule.dest_ip else []

            if not src_ips or not dst_ips:
                print(f"Skipping rule {rule.id}: No source or destination IPs")
                continue

            # Check for matching interfaces
            matching_pairs = check_routes_across_firewalls(
                src_firewall_ip=rule.srcFirewallIP,
                dst_firewall_ip=rule.dstFirewallIP,
                username=username,
                password=password,
                secret=secret,
                src_ips=src_ips,
                dst_ips=dst_ips
            )

            # Update inLine field if any pair has matching interfaces
            if matching_pairs:
                rule.inLine = "inline"
                db.commit()
                print(f"Updated rule {rule.id}: inLine set to 'inline' for pairs {matching_pairs}")
            else:
                # Optionally set to "not inline" if no matches
                if rule.inLine != "inline":
                    rule.inLine = "not inline"
                    db.commit()
                    print(f"Updated rule {rule.id}: inLine set to 'not inline'")

    except Exception as e:
        print(f"Error processing rules: {str(e)}")
        db.rollback()
    finally:
        db.close()


"""
combination 
inline 

"""