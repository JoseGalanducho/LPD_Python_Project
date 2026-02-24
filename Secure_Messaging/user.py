#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# user, this class controlls the messaging system on the user side
#############################################################################################
#Imports
import os.path
import pickle
import socket
import threading
import rsa
from termcolor import colored
from Helper_Classes import KeyManager

#Constants
PRIVATE_KEYS = "rsa_secret_"
PUBLIC_KEYS = "rsa_public_"

#############################################################################################
# user_begin
# @args: username -> the user to disconnect
# @args: server_ip -> server dcomunication IP
# @args: server_port -> server communication port
# @return:
# Receives user data and starts the user
# #connection and communication with the server
##############################################################################################
def user_begin(server_ip, server_port, username):
    public_key, private_key = KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)

    user = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        user.connect((server_ip, server_port))
    except:
        print("Connection error")
        return
    print(colored(f"{username} connected to server", "green"))
    print(colored(f"type '/leave' to leave the chat.","red"))

    server_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
    user.send(public_key.save_pkcs1("PEM"))

    message = rsa.decrypt(user.recv(1024), private_key).decode()
    user.send(rsa.encrypt(username.encode(), server_public_key))

    in_thread = threading.Thread(target=read_message,args=(user, private_key))
    in_thread.daemon=True
    in_thread.start()

    out_thread = threading.Thread(target=send_message,args=(user,message,private_key))
    out_thread.daemon = True
    out_thread.start()

    return user

#############################################################################################
# decode_messages
# @args: username -> user username for the server
# @args: messages -> list of messages
# @return:
# Returns a list of messages decoded
##############################################################################################
def decode_messages(username, messages):
    public_key, private_key =  KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)
    decoded_messages = []
    for message in messages:
        decoded_messages.append(rsa.decrypt(message, private_key).decode())
    return decoded_messages

#############################################################################################
# read_message
# @args: user -> the user to receive the message (socket)
# @args: user_private_key -> the user private key to decode the message
# @return:
# Receives messages from the server and decodes the message
##############################################################################################
def read_message(user, user_private_key):
    while True:
        try:
            message = rsa.decrypt(user.recv(1024), user_private_key).decode()
            if message == "/leave":
                user.close()
                break
            else:
                print(message)
        except:
            print("System error, closing chat.")
            user.close()
            break

#############################################################################################
# send_message
# @args: user -> the user to send the message (socket)
# @args: server_public_key -> the server key to encrypt the message
# @args: username -> the user username to show on the server
# @return:
# Receives input message from user to write on the server chat
##############################################################################################
def send_message(user, server_public_key, username=None):
    while True:
        message = input(f"{username} > {input('')}")
        user.send(rsa.encrypt(message.encode(), server_public_key))

#############################################################################################
# login
# @args: server_ip -> server network IP
# @args: server_port -> server communication port
# @args: username -> the user username registered on the server
# @args: password -> user password
# @return:
# Return the result of the login, either True for success or False for failed login
##############################################################################################

def login(server_ip, server_port, username, password):
    user = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        user.connect((server_ip, server_port))
    except:
        print("Server not found")
        return False

    user_public_key, user_private_key =  KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)

    server_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
    user.send(user_public_key.save_pkcs1("PEM"))

    user.send(rsa.encrypt(f"/login {username} {password}".encode(), server_public_key))

    response = rsa.decrypt(user.recv(1024), user_private_key).decode()

    if response == "SUCCESS":
        print(colored(response, "green"))
        return True
    else:
        print(colored(response, "red"))
        return False

#############################################################################################
# register
# @args: server_ip -> server network IP
# @args: server_port -> server communication port
# @args: username -> the user username registered on the server
# @args: password -> user password
# @return:
# Return the result of the register, either True for success or False for failed login
##############################################################################################
def register(server_ip, server_port, username, password):

    user = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user.connect((server_ip, server_port))

    user_public_key, user_private_key =  KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)

    server_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
    user.send(user_public_key.save_pkcs1("PEM"))
    user.send(rsa.encrypt(f"/register {username} {password}".encode(), server_public_key))
    print(f"/register {username} {password}")
    response = rsa.decrypt(user.recv(1024), user_private_key).decode()

    if response == "SUCCESS":
        print("User registered!")
    else:
        print("Registration Error!")

############################################################################################
# get_message_history
# @args: server_ip -> server network IP
# @args: server_port -> server communication port
# @args: username -> the user username registered on the server
# @return:
# Prints the historic of messages for the user
##############################################################################################
def get_message_history(server_ip, server_port, username):

    user= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user.connect((server_ip, server_port))

    user_public_key, user_private_key =  KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)

    server_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
    user.send(user_public_key.save_pkcs1("PEM"))

    user.send(rsa.decrypt(f"/history {username}".encode(), server_public_key))

    historic = b""
    while True:
        chunk = user.recv(1024)
        if not chunk:
            break

        historic += chunk
    messages = pickle.loads(historic)
    messages = decode_messages(username, messages)

    print("\n")
    print(colored(f"{username} historic:", "green"))
    for message in messages:
        print(colored(message, "green"))

############################################################################################
# get_users
# @args: server_ip -> server network IP
# @args: server_port -> server communication port
# @args: username -> the user username registered on the server
# @return:
# Prints the list of users in the server
##############################################################################################
def get_users(server_ip, server_port, username):

    user= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user.connect((server_ip, server_port))

    user_public_key, user_private_key =  KeyManager.get_user_keys(username, PUBLIC_KEYS, PRIVATE_KEYS)
    server_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
    user.send(user_public_key.save_pkcs1("PEM"))

    user.send(rsa.encrypt(f"/users".encode(), server_public_key))

    user_list = b""
    while True:
        chunk = user.recv(1024)
        if not chunk:
            break
        user_list += chunk
    users = pickle.loads(rsa.decrypt(user_list, user_private_key))

    print("\n")
    print(colored(f"User List:", "green"))
    for user in users:
        print(user)
