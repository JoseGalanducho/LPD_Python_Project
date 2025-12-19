#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# LogAnalyzer, this class reads and analyses log files, returnin an anal
#############################################################################################

####################################################################
# Port Scan Method
# @args: IPs, ports, view, print_file
#IPs -> IP list |  ports -> port list | view -> 0 or 1 (console or GUI) | print_file = file path to print results to a file
###################################################################
from termcolor import colored

def log_analyzer():
    print(colored("---------- Log Analyzer ----------","green"))
    results=[]

