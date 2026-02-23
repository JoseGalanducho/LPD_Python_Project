#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# main, this function starts the program, and shows the main menu and it's options
#############################################################################################
from Log_Analyzer import LogAnalyzer
from SYN_Flood import SYNFlood
from Helper_Classes import ArgumentMaker
from Port_Scanner import  portscan
from Secure_Messaging import server
from Secure_Messaging import user
from termcolor import colored
from UDP_Flood import UDPFlood


def main():
    while True:
        print(colored(f"=================================================================","green"))
        print(colored(f"==                       Select an option:                     ==", "green"))
        print(colored(f"=================================================================", "green"))
        print(colored(f"1-Port Scan", "green"))
        print(colored(f"2-UDP Flood", "green"))
        print(colored(f"3-SYN Flood", "green"))
        print(colored(f"4-Log Analyzer", "green"))
        print(colored(f"5-Secure Messaging Server", "green"))
        print(colored(f"6-Secure Messaging User Login", "green"))
        print(colored(f"7-User Login", "green"))
        print(colored(f"8-Register User", "green"))
        print(colored(f"9-Get Messages", "green"))
        print(colored(f"q-Close Program", "red"))

        option = input(colored(f"->", "green"))
        if option == "1":
            IPs, ports = ArgumentMaker.ips_and_ports()
            portscan.port_scan(IPs, ports, 0, 0)
        if option == "2":
            IPs =  ArgumentMaker.insert_IP()
            ports = ArgumentMaker.insert_port()
            pckt_size = int(input("Enter packet size:(default=1024)") or 1024)
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            UDPFlood.UDPFlood(IPs, int(ports), pckt_size, pckt_quantity)
        if option == "3":
            IPs = ArgumentMaker.insert_IP()
            ports = ArgumentMaker.insert_port()
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            SYNFlood.SYN_Flood(IPs, ports, pckt_quantity)
        if option == "4":
            service = ""
            file_path = input("Enter log file path:")
            while service != "HTTP" and service != "SSH":
                service = input("Enter service (HTTP or SSH):")
                service = service.upper()
                output = input("Enter output format (PDF, CSV, Console:")
                output = output.upper()
            LogAnalyzer.log_analyzer(file_path, service, output)
        elif option == "5":
            print(colored(f'Insert IP address for server communication, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert port for server communication, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            server.start_server(IP, int(port))
        elif option == "6":
            print(colored(f'Insert server IP address, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert server port, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            username = input("Enter username")
            password = input("Enter password")
            user.login(IP, int(port), username, password)
        elif option == "7":
            server.get_local_ip()

        elif option == "8":
            print(colored(f'Insert server IP address, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert server port, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            username = input("Enter username")
            password = input("Enter password")
            server.get_local_ip()
            registered = user.register(IP, int(port), username, password)
            if registered:
                print(colored(f"User {username} successfully registered!", "green"))
            else:
                print(colored(f"User {username} not registered!", "red"))
        elif option == "q":
            print(colored(f"Closing Program\n", "red"))
            break

        else:
            print(colored(f"Invalid Option", "yellow"))

if __name__ == "__main__":
    main()