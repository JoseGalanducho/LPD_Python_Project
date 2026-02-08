#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# main, this function starts the program, and shows the main menu and it's options
#############################################################################################
from Log_Analyzer import LogAnalyzer
from SYN_Flood import SYNFlood
from Helper_Classes import ArgumentMaker
from Port_Scanner import  portscan
from termcolor import colored
from UDP_Flood import UDPFlood


def main():
    while True:
        print(colored(f"=================================================================","green"))
        print(colored(f"==                       Select an option:                     ==", "green"))
        print(colored(f"=================================================================", "green"))
        print(colored(f"1-Port Scan\n", "green"))
        print(colored(f"2-UDP Flood\n", "green"))
        print(colored(f"3-SYN Flood\n", "green"))
        print(colored(f"4-Log Analyzer\n", "green"))
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
                service = input("Entrer service (HTTP or SSH):")
                service = service.upper()
            LogAnalyzer.log_analyzer(file_path, service)

if __name__ == "__main__":
    main()