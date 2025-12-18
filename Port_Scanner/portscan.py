import socket
from termcolor import colored
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import tqdm
import MainMenu

#################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# PortScan this class executes ports scans and saves or prints the result
#################################################################################

####################################################################
# Port Scan Method
# @args: IPs, ports, view, print_file
#IPs -> IP list |  ports -> port list | view -> 0 or 1 (console or GUI) | print_file = file path to print results to a file
###################################################################
def port_scan(IPs=[""], ports=[""], view="", print_file="" ):

    report = []

    if IPs is None:
        print(colored("No IP list provided!", "red"))

    if ports is None:
        print(colored("No ports provided, default port list will be aplied (22, 25, 80, 443, 8080)\n", "red"))
        ports = [22 ,25, 80, 443, 8080]
    total_scans = len(IPs)*len(ports)
    index = 0
    print(colored("Port scanner running...","green"))
    for ip in IPs:

        for port in ports:
            index +=1
            percentage = round(100*(index/total_scans),1)
            print(colored(f"Scanning {percentage}%","green"))
            print(colored(f"Scanning-> {ip}:{port}", "green"))
            sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sckt.settimeout(1)
            try:
                sckt.connect((ip, int(port)))
                port_result = f"{ip}:{port} ==> Open"
                report.append(port_result)
            except (socket.timeout, ConnectionRefusedError):
                pass
            finally:
                sckt.close()
    for result in report:
        if len(report) == 0:
            print(colored("No avaliable port in the selected IP from the list"))
        print(colored(f"{result}", "green"))
    MainMenu.main()