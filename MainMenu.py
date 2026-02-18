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
        print(colored(f"5-Secure Message Server", "green"))
        print(colored(f"6-Secure Message Register Server", "green"))
        print(colored(f"7-Secure Message Login Server", "green"))
        print(colored(f"8-Secure Message User", "green"))
        print(colored(f"q-Exit", "red"))
        option = input(colored(f"->", "green"))
        if option == "1":
            IPs, ports = ArgumentMaker.ips_and_ports()
            portscan.port_scan(IPs, ports, 0, 0)
        elif option == "2":
            print(colored(f'Insert IP address to UPD Flood (DoS), or 0(zero) to exit.', "green"))
            IPs =  ArgumentMaker.insert_IP()
            print(colored(f'Insert port for UPD Flood (DoS), or 0(zero) to exit.', "green"))
            ports = ArgumentMaker.insert_port()
            pckt_size = int(input("Enter packet size:(default=1024)") or 1024)
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            UDPFlood.UDPFlood(IPs, int(ports), pckt_size, pckt_quantity)
        elif option == "3":
            IPs = ArgumentMaker.insert_IP()
            ports = ArgumentMaker.insert_port()
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            SYNFlood.SYN_Flood(IPs, ports, pckt_quantity)
        elif option == "4":
            service = ""
            file_path = input("Enter log file path:")
            while service != "HTTP" and service != "SSH":
                service = input("Entrer service (HTTP or SSH):")
                service = service.upper()
            LogAnalyzer.log_analyzer(file_path, service)
        elif option == "5":
            print(colored(f'Insert IP address for server communication, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert port for server communication, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            server.start_server(IP, int(port))
        elif option == "6":
            server.get_local_ip()
        elif option == "7":
            server.get_local_ip()
        elif option == "8":
            server.get_local_ip()

        elif option == "q":
            print(colored(f"Closing Program\n", "red"))
            break

        else:
            print(colored(f"Invalid Option", "yellow"))

if __name__ == "__main__":
    main()