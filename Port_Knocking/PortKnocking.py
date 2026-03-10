#############################################################################################
# @Author: Jose Manuel Batista Galanducho
# PortKnocking.py
# Simple client for port knocking before SSH access
#############################################################################################

import socket
import time
from termcolor import colored

def port_knocking(remote_ip, sequence, open_ssh):
    """
    PortKnocking Function
    Send the knock sequence to the target server.
    :param sequence: Sequence of ports to knock on (default: [1234, 2345, 3456]).
    :param remote_ip: IP address of the target server (default: 192.168.1.223).
    :param open_ssh: Whether to open or close the SSH port (default: True).
    """
    sequence = sequence.split(",")
    if open_ssh == "C":
        sequence.reverse()

    for port in sequence:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set the socket to non-blocking mode
            sock.setblocking(False)
            # Send the knock to the target server with connect_ex so it doesn't wait for a response
            sock.connect_ex((remote_ip, int(port)))
            print(colored(f"Knock sent to port {port}", "yellow"))
            sock.close()
            time.sleep(1)
        except Exception as e:
            print(colored(f"Error sending knock to port {port}: {e}", "red"))
            return

    print(colored("Knock sequence sent.", "green"))
