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
        print(colored(f"5-Start Secure Messaging Server", "green"))
        print(colored(f"6-Start Secure Messaging Login Server", "green"))
        print(colored(f"7-Start Secure Messaging Register Server", "green"))
        print(colored(f"8-Register User", "green"))
        print(colored(f"9-Connect User to Secure Messaging", "green"))
        print(colored(f"10-Get Messages", "green"))
        print(colored(f"q-Close Program", "red"))
        option = input(colored(f"->", "green"))

        ##Portscan
        if option == "1":
            IPs, ports = ArgumentMaker.ips_and_ports()
            portscan.port_scan(IPs, ports, 0, 0)
        ## UDP Flood
        elif option == "2":
            IPs =  ArgumentMaker.insert_IP()
            ports = ArgumentMaker.insert_port()
            pckt_size = int(input("Enter packet size:(default=1024)") or 1024)
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            UDPFlood.UDPFlood(IPs, int(ports), pckt_size, pckt_quantity)
        ## SYN Flood
        elif option == "3":
            IPs = ArgumentMaker.insert_IP()
            ports = ArgumentMaker.insert_port()
            pckt_quantity = int(input("Enter packet quantity:(default=20)") or 20)
            SYNFlood.SYN_Flood(IPs, ports, pckt_quantity)
        ## Log Analyzer
        elif option == "4":
            service = ""
            file_path = input("Enter log file path:")
            while service != "HTTP" and service != "SSH":
                service = input("Enter service (HTTP or SSH):")
                service = service.upper()
                output = input("Enter output format (PDF, CSV, Console:")
                output = output.upper()
            LogAnalyzer.log_analyzer(file_path, service, output)
        ## Secure Messaging server
        elif option == "5":
            print(colored(f'Insert IP address for server communication, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert port for server communication, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            server.start_server(IP, int(port))
            ## Login Server
        elif option == "6":
            print(colored(f'Insert server IP address, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert server port, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            server.start_login_server(IP, int(port))
            ## Register Server
        elif option == "7":
            print(colored(f'Insert IP address for server communication, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert port for server communication, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            server.start_register_server(IP, int(port))
            ## Register User
        elif option == "8":
            print(colored(f'Insert server IP address, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert server port, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            username = input("Enter username: ")
            password = input("Enter password: ")
            user.register(IP, int(port), username, password)
            ## Login User
        elif option == "9":
            print(colored("Login to messaging server", "blue"))
            print(colored(f'Insert login server IP address.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert login server port.', "green"))
            port = ArgumentMaker.insert_port()
            username = input("Enter username: ")
            password = input("Enter password: ")
            if user.login(IP, int(port), username, password) == True:
                print(colored(f'Insert chat server IP address.', "green"))
                chat_server_IP = ArgumentMaker.insert_IP()
                print(colored(f'Insert chat server port.', "green"))
                chat_server_port = ArgumentMaker.insert_port()
                chat_user = user.user_begin(chat_server_IP, int(chat_server_port), username)
                if chat_user:
                    print(colored(f'Message server active, you can chat now.', "blue"))
                    while chat_user:
                        pass
                else:
                    print(colored(f'Message server not active, try again.', "red"))
                    continue
            ## Login User
        elif option == "10":
            print("Not Done")
            print(colored(f'Insert server IP address, or 0(zero) to exit.', "green"))
            IP = ArgumentMaker.insert_IP()
            print(colored(f'Insert server port, or 0(zero) to exit.', "green"))
            port = ArgumentMaker.insert_port()
            username = input("Enter username: ")
            user.get_message_history(IP, int(port), username)

        elif option == "q":
            print(colored(f"Closing Program\n", "red"))
            break
        else:
            print(colored(f"Invalid Option", "yellow"))

if __name__ == "__main__":
    main()