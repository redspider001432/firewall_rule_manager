import logging
import re
from fastapi import HTTPException
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

def show_failover_state(ip, username, password, secret, context_name=None) -> dict:
    """
    Check the failover state of a Cisco ASA firewall and optionally switch to a context.
    
    Args:
        ip (str): IP address of the firewall.
        username (str): Username for SSH authentication.
        password (str): Password for SSH authentication.
        secret (str): Enable secret for privileged mode.
        context_name (str, optional): Context name to switch to after checking failover state.
    
    Returns:
        dict: Contains 'is_active' (bool) indicating if the firewall is active (Group 1 and Group 2 are Active),
              and 'message' (str) with status details.
    
    Raises:
        HTTPException: If connection or command execution fails.
    """
    if not ip:
        logging.info("No IP provided for failover state check.")
        return {"is_active": True, "message": "No IP provided, assuming active."}

    device = {
        'device_type': 'cisco_asa',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()

            # Command 1: Change to system context
            net_connect.send_command("change system", expect_string=r"#")
            logging.debug(f"Switched to system context on {ip}")

            # Command 2: Show failover state
            output = net_connect.send_command("show failover state")
            logging.debug(f"Failover state output from {ip}: {output}")

            # Parse output using regex
            lines = output.splitlines()
            this_host_section = None
            for i, line in enumerate(lines):
                if re.match(r"^\s*This host\s*-", line):
                    this_host_section = lines[i:]
                    break

            if not this_host_section:
                logging.warning(f"Could not find 'This host' section in failover state output from {ip}")
                return {
                    "is_active": False,
                    "message": "Failed to parse failover state: 'This host' section not found. Please select an active firewall."
                }

            # Check Group 1 and Group 2 states
            group1_active = False
            group2_active = False
            for line in this_host_section:
                if "Group 1" in line and "Active" in line:
                    group1_active = True
                if "Group 2" in line and "Active" in line:
                    group2_active = True

            if group1_active and group2_active:
                # Command 3: Change to specified context (if provided)
                if context_name:
                    net_connect.send_command(f"change context {context_name}", expect_string=r"#")
                    logging.debug(f"Switched to context '{context_name}' on {ip}")
                return {
                    "is_active": True,
                    "message": f"Firewall {ip} is active (Group 1 and Group 2 are Active)."
                }
            else:
                return {
                    "is_active": False,
                    "message": f"Firewall {ip} is not fully active (Group 1: {'Active' if group1_active else 'Not Active'}, Group 2: {'Active' if group2_active else 'Not Active'}). Please select an active firewall."
                }

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logging.error(f"Failed to connect to firewall {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        logging.error(f"Failed to execute commands on {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to execute commands on {ip}: {str(e)}")