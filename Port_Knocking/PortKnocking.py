#############################################################################################
# @Author: Jose Manuel Batista Galanducho
# PortKnocking.py
# Simple client for port knocking before SSH access
#############################################################################################

import socket
import time
from termcolor import colored
from Helper_Classes.ArgumentMaker import IP_check, port_check


def _parse_sequence(raw_sequence):
    ports = []
    if not raw_sequence:
        return ports
    for port in raw_sequence.split(","):
        cleaned = port.strip()
        if cleaned == "":
            continue
        if not port_check(cleaned):
            raise ValueError(f"Invalid port in sequence: {cleaned}")
        ports.append(int(cleaned))
    return ports


def port_knock_client(target_ip, knock_sequence, protocol="tcp", delay=0.5):
    """
    Send a configurable port knocking sequence to target_ip.
    :param target_ip: IPv4 destination
    :param knock_sequence: list[int] of ports
    :param protocol: "tcp" or "udp"
    :param delay: seconds between knocks
    :return: bool
    """
    if not IP_check(target_ip):
        print(colored("Invalid target IP address.", "red"))
        return False

    if not knock_sequence:
        print(colored("Empty knock sequence.", "red"))
        return False

    protocol = protocol.lower().strip()
    if protocol not in ["tcp", "udp"]:
        print(colored("Protocol must be tcp or udp.", "red"))
        return False

    print(colored(f"Starting port knocking to {target_ip}", "green"))
    print(colored(f"Sequence: {knock_sequence} | Protocol: {protocol.upper()}", "green"))

    for index, port in enumerate(knock_sequence, start=1):
        try:
            if protocol == "tcp":
                sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sckt.settimeout(0.8)
                sckt.connect_ex((target_ip, int(port)))
            else:
                sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sckt.sendto(b"KNOCK", (target_ip, int(port)))
            print(colored(f"[{index}/{len(knock_sequence)}] Knock sent to {target_ip}:{port}", "yellow"))
        except Exception as e:
            print(colored(f"Error knocking {target_ip}:{port} -> {e}", "red"))
            return False
        finally:
            try:
                sckt.close()
            except Exception:
                pass

        time.sleep(delay)

    print(colored("Knock sequence completed.", "green"))
    return True


def test_ssh_port(target_ip, ssh_port=22, timeout=2):
    """
    Simple connectivity check to verify if SSH port is reachable.
    """
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(timeout)
        result = sckt.connect_ex((target_ip, int(ssh_port)))
        if result == 0:
            print(colored(f"SSH port {ssh_port} is OPEN on {target_ip}.", "green"))
            return True
        print(colored(f"SSH port {ssh_port} is CLOSED/FILTERED on {target_ip}.", "red"))
        return False
    except Exception as e:
        print(colored(f"Error testing SSH port: {e}", "red"))
        return False
    finally:
        try:
            sckt.close()
        except Exception:
            pass


def interactive_client():
    """
    Interactive execution for the project menu.
    """
    target_ip = input("Target Linux IP: ").strip()
    sequence_input = input("Knock sequence (comma separated, ex.: 7000,8000,9000): ").strip()
    protocol = input("Protocol [tcp/udp] (default=tcp): ").strip() or "tcp"
    delay_input = input("Delay between knocks in seconds (default=0.5): ").strip() or "0.5"
    ssh_port_input = input("SSH port to test (default=22): ").strip() or "22"

    try:
        delay = float(delay_input)
    except ValueError:
        print(colored("Invalid delay value.", "red"))
        return

    try:
        ssh_port = int(ssh_port_input)
    except ValueError:
        print(colored("Invalid SSH port.", "red"))
        return

    try:
        knock_sequence = _parse_sequence(sequence_input)
    except ValueError as e:
        print(colored(str(e), "red"))
        return

    if port_knock_client(target_ip, knock_sequence, protocol, delay):
        test_ssh_port(target_ip, ssh_port)
