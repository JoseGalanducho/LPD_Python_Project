#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# ArgumentMaker.py prepares the input for some functions
#############################################################################################

#############################################################################################
# ips_and_ports
# @args:
# @return: IP lista and Port List
# This method prepares the input for the port scan, receives the ip list and ports to scan,
# if values are correct, it calls for the port scan with inserted values.
##############################################################################################

from termcolor import colored

def ips_and_ports():
    '''
    Ips and Ports function
    Ask the users to insert an IP or list of IPs and a port, or list of ports.
    Prepares the inserted values and returns a list of IPs and a list of ports.
    :return: IP list and Port list.
    '''
    IP_list = []
    gate_list = []
    gate="1"
    print(colored(f'Insert IP addresses to be scaned.', "green"))
    IP = "1"
    #--------------------Get IP List ------------------------------------------
    while IP != "0":
        print(colored(f'Insert IPv4 IP\n Insert 0(zero) to exit.', "green"))
        IP=input("IP:")
        if IP != "0":
            valid = IP_check(IP)
            if valid == False:
                print(colored(f'IP not valid!',"red"))
            else:
                IP_list.append(IP)
    #----------------------------Get Gate List    -------------------------------------
    while gate != "0":
        print(colored(f"Insert gates to scan insert first-last for a gate list (Ex.:22-1000)\n Insert 0(zero) to exit.", "green"))
        gate=input("Gate:")
        if gate != "0":
            valid, gate_list_checked = check_port_list(gate)
            if valid > 0:
                for new_gate in gate_list_checked:
                    gate_list.append(new_gate)
            if valid == 0:
                print(colored("Gate input not valid!","red"))
    if not IP_list:
        IP_list = None
    if not gate_list:
        gate_list = None
    return IP_list, gate_list

#############################################################################################
# insert_IP
# @args:
# @return: IP
# This method prepares the input for the port scan, receives the ip list and ports to scan,
# if values are correct, it calls for the port scan with inserted values.
##############################################################################################
def insert_IP():
    '''
    Insert IP
    Asks the user to insert an IP and verifies if it is valid, if the user inserts 0 it stops.
    :return: IP or null if user stops the function
    '''
    valid_IP = "1"
    # --------------------Get IP List ------------------------------------------
    while valid_IP == "1":
        print(colored(f'Insert a valid IPv4 IP.', "green"))
        IP = input("IP:")
        if not IP_check(IP):
            print(colored(f'IP not valid!', "red"))
        else:
            return  IP
        if IP == "0":
            break

#############################################################################################
# insert_port
# @args:
# @return: port
# This method reads the user input fot the IP address
##############################################################################################
def insert_port():
    '''
    Asks the user to insert a port and verifies if it is valid, if the user inserts 0 it stops.
    :return:  Communication port or null if user stops the function
    '''
    valid_port = "1"
    # --------------------Get port List ------------------------------------------
    while valid_port == "1":
        print(colored(f'Insert a valid network port.', "green"))
        port = input("Port:")
        if not port_check(port):
            print(colored(f'Port not valid!', "red"))
        else:
            return  port
        if port == "0":
            break

#############################################################################################
# IPcheck
# @args: IP
# @return: (bool)valid
# Checks if IP inserted is valid.
#############################################################################################
def IP_check(IP):
    '''
    IP check function
    Receives and IP and verifies if it is valid.
    :param IP: String containing an IP
    :return: True if valid IP, false otherwise
    '''
    valid = True
    IP_segments = IP.split(".")
    IP_segments
    if len(IP_segments) == 4:
        for segment in IP_segments:
            if int(segment) > 255 or  int(segment) < 0:
                valid = False
    else:
        valid = False
    return valid

#############################################################################################
# port_check
# @args: port
# @return: (bool)valid
# Checks if network port is correct
#############################################################################################
def port_check(port):
    '''
    Port Check function
    Receives and port and verifies if it is valid.
    :param port: String with a port number.
    :return: True if valid, false otherwise.
    '''
    valid = True
    try:
        if int(port) > 0 and int(port) <= 65535:
            return valid
    except Exception as e:
        print(colored(f"Inserted port value not valid.", "red"))

#############################################################################################
# check_port_list
# @args: port_list
# @return: (int)valid, (list) gatelistcompiled
# Checks if gate or gate list inserted is valid and compiles it into a list.
#############################################################################################

def check_port_list(port_list):
    '''
    Check port list function
    Receives a starting port and ending port, and creates a list with all the ports between them.
    :param port_list: Initial and final port separated by "-".
    :return: A list of ports or 0 if the list is not valid.
    '''
    valid = 1
    port_list_compiled=[]
    if "-" in port_list:
        port_list_segments = port_list.split("-")
        if len(port_list_segments) == 2 and int(port_list_segments[0]) < int(port_list_segments[1]):
            if int(port_list_segments[1]) > 65535:
                port_list_segments[1]= "65535"
            if int(port_list_segments[0]) < 1:
                port_list_segments[0] = "1"
            for i in range(int(port_list_segments[0]),int(port_list_segments[1])):
                port_list_compiled.append(str(i))
    else:
        if isinstance(int(port_list), int) == True:
            port_list_compiled.append(port_list)
        else:
            valid = 0

    return valid, port_list_compiled

#############################################################################################
# progress_print
# @args: fase
# @return: simbol
# receives a value from 1 to 4 and returns a string to print, showing the user that progress is being made.
#############################################################################################

def progress_print(fase):
    '''
    Progress Print function
    This function creates a visual effect to give the user some feedback.
    :param fase: Input to select the simbol to print.
    :return:
    '''
    _ = fase
    simbol = "--"
    if fase < 0:
        _ = 1
    elif fase > 4:
        _ = 4

    if( _ == 1):
        simbol = "\\"
    elif( _ == 2):
        simbol = "╏"
    elif( _ == 3):
        simbol = "/"
    elif ( _ == 4):
        simbol="--"

    return simbol

#############################################################################################
# port_list
# @args: port_sequence
# @return:
# Receives a list of ports and tests if it is a valid list.
#############################################################################################

def port_list(port_sequence):
    '''
    Port List Function
    Receives a list of ports separated by spaces, and creates a list for the port knocking sequence, and checks if all the ports are
    valid.
    :param port_sequence: List of ports
    :return:
    '''
    port_array = port_sequence.split(" ")
    for port in port_array:
        if port_check(port) != True:
            return False
    return True