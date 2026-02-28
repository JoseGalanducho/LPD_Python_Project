#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# server, this class controlls the secure messaging system server
#############################################################################################
#Imports
import hashlib
import os.path
import pickle
import socket
import threading
import json
from termcolor import colored
from Helper_Classes import KeyManager
import rsa

#system files
MESSAGE_LOG = "Secure_Messaging/message_log_"
USERS_REGISTER = "Secure_Messaging/users_register.json"
PRIVATE_KEYS = "Secure_Messaging/server_secret_keys.pem"
PUBLIC_KEYS = "Secure_Messaging/server_public_keys.pem"

# non constant variables
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
users_list = []
username_list = []
public_key_list = []

#############################################################################################
# message_handler
# @args: user -> the user who sent the message
# @args: private_key -> server private key
# @return:
# Receives a user, and the server private key. Handles the message decryption, transmission and
# user chat exit.
##############################################################################################
def message_handler (user, private_key):
    """
    Message handler function
    Processes and manages the messages sent by the users
    :param user: The message sender
    :param private_key: Server private key
    :return:
    """
    while True:
        try:
            message = rsa.decrypt(user.recv(1024), private_key)
            print(f"message: {message}")
            if not message:
                user_logout(user)

            if '/leave' in message.decode():
                user_index = users_list.index(user)
                user.send(rsa.encrypt('/leave command inserted.'.encode(), public_key_list[user_index]))
                user_logout(user)
                break
            broadcast(message, user)

        except Exception as e:
            print(colored(f"[-] Error: {e}", "red"))
            user_logout(user)
            break

#############################################################################################
# broadcast
# @args: user -> user that sent the message
# @args: message -> user message to broadcast
# @return:
# Receives a user and message, and sends the message to all users.
##############################################################################################
def broadcast(message, origin_user):
    """
    broadcast function
    Sends a message to all users except the one who sent it
    :param message: Message to broadcast
    :param origin_user: User that sent the message
    :return:
    """
    for user  in users_list:
        index = users_list.index(user)
        if user != origin_user:
            message_send = rsa.encrypt(message, public_key_list[index])
            user.send(message_send)
    save_message(message)

#############################################################################################
# save_message
# @args: message -> message to be saved
# @return:
# Receives a message and stores it into a log file.
##############################################################################################
def save_message(message):
    """
    save_message function
    Receives a message and stores it on a file encripted
    :param message: the message to save
    :return:
    """
    for user in users_list:
        index = users_list.index(user)
        username = username_list[index]
        public_key = public_key_list[index]
        file_path = MESSAGE_LOG+username+".json"
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                json.dump({"messages":[rsa.encrypt(message, public_key).hex()]}, file)
        else:
            with open(file_path, "r") as file:
                message_list = json.load(file)
                message_list["messages"].append(rsa.encrypt(message, public_key).hex())
            with open(file_path, "w") as file:
                json.dump(message_list, file)

#############################################################################################
# user_logout
# @args: user -> user to logout
# @return:
# Receives a user, and removes it from the chat.
##############################################################################################
def user_logout(user):
    """
    user_logout function
    Disconnects and removes a user from the chat system.
    :param user: User to remove from the system.
    :return:
    """
    index = users_list.index(user)
    users_list.remove(user)
    username = username_list[index]
    username_list.remove(username)
    public_key_list.remove(public_key_list[index])
    print(colored(f"{username} disconnected from the server!", "red"))
    broadcast(f'{username} left the chat!'.encode(), user)
    user.close()

#############################################################################################
# user_input
# @args: public_key -> server public key,
# @args: private_key -> server private key
# @return:
# Receives input from users, starts a new thread for each client.
##############################################################################################
def user_input(public_key, private_key):
    """
    user_input function
    receives the users inputs, both messages and commands, and processes them.
    :param public_key: Server public key
    :param private_key: Server private key
    :return:
    """
    while True:
        try:
            user, address = server.accept()
            print(colored(f"[+] Username: {user} -> Address: {str(address)}", "green"))
            user.send(public_key.save_pkcs1("PEM"))
            user_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
            user.send(rsa.encrypt('REQUEST_USER'.encode(), user_public_key))
            username = rsa.decrypt(user.recv(1024), private_key).decode()
            username_list.append(username)
            users_list.append(user)
            public_key_list.append(user_public_key)
            print(colored(f"[+] Username: {username} is connected.", "green"))
            broadcast(f"{username} is connected.".encode(), user)
            user.send(rsa.encrypt('Connected to server!'.encode(), user_public_key))
            thread = threading.Thread(target=message_handler, args=(user, private_key,))
            thread.start()
        except Exception as e:
            print(colored(f"[-] Error: {e}", "red"))
            server.close()
            break

#############################################################################################
# get_local_ip
# @return:local_ip -> Machine local IP
# Retrives machine local IP
##############################################################################################
def get_local_ip():
    """
    get_local_ip function
    Gets the machine IP and returns it.
    :return: Server IP
    """
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(local_ip)

#############################################################################################
# start_server
# @args: host, pot
# @return:
# This method starts the server, generating keys and starting to listening to the communication port
##############################################################################################
def start_server(host, port):
    """
    start_server function
    Starts the messaging server.
    :param host:
    :param port:
    :return:
    """
    server.bind((host, port))
    public_key, private_key = KeyManager.get_rsa_keys(PUBLIC_KEYS, PRIVATE_KEYS)
    server.listen()
    print(colored(f"Server active on-> {host}:{port}\n", "green"))
    user_input(public_key, private_key)

#############################################################################################
# register_user
# @args: username -> user name on the chat
# @args: password -> user password
# @return:
# The systems receives the username and password and registers the new user.
##############################################################################################
def register_user(username, password):
    """
    register_user function
    Registers a new user on the server.
    :param username: User username.
    :param password: User password
    :return: True for success ot False for failed atempt.
    """

    if not os.path.exists(USERS_REGISTER):
        with open(USERS_REGISTER, "w") as file:
            json.dump({}, file)

    with open(USERS_REGISTER, "r") as file:
        users_file = json.load(file)

    if username in users_file:
        print(colored("User already registered.", "yellow"))
        return False

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users_file[username] = hashed_password

    with open(USERS_REGISTER, "w") as file:
        json.dump(users_file, file)
    print(colored(f"User {username} registered.", "green"))
    return True

#############################################################################################
# user_list
# @args:
# @return:
# Reads the user list file and prints the result.
##############################################################################################
def user_list():
    """
    user_list function
    Gets the list of registered users.
    :return: List of registered users.
    """
    if os.path.exists(USERS_REGISTER):
        with open(USERS_REGISTER, "r") as file:
            users_list = json.load(file)
            for user in users_list:
                print(colored(f"User: {user}", "green"))

#############################################################################################
# get_encrypted_message
# @args: username -> user username on the server
# @return:
# Reads the registered messages from a user and returns the messages.
##############################################################################################

def get_encrypted_messages(username):
    """
    get_encrypted_messages function
    Reads the messages the user chat history and returns a list of messages.
    :param username: Requesting user username
    :return: List of messages.
    """
    if os.path.exists(USERS_REGISTER):
        with open(USERS_REGISTER, "r") as file:
            users = json.load(file)
    else:
        print("No users register detected.")
        return

    if username not in users:
        print(colored(f"User {username} not registered.", "red"))
        return

    if os.path.exists(MESSAGE_LOG+username+".json"):
        with open(MESSAGE_LOG+username+".json", "r") as file:
            messages = json.load(file)["messages"]
    else:
        print(colored(f"No messages registered.", "red"))
        return

    messages_registered = []
    for message in messages:
        messages_registered.append(bytes.fromhex(message))

    return messages_registered

#############################################################################################
# start_login_server
# @args: server_ip -> the IP for the server to listen on
# @args: server_port -> the port for the server to listen on
# @return:
# Starts the server that allows for users to login.
##############################################################################################

def start_login_server(server_ip, server_port):
    """
    start_login_server function
    Starts the login server and processes user login.
    :param server_ip: IP where the server receives communications.
    :param server_port: Network port where the server receives communications.
    :return:
    """
    server.bind((server_ip, server_port))
    server.listen()
    print(colored(f"Login server active on-> {server_ip}:{server_port}\n", "green"))
    server_public_key, server_private_key = KeyManager.get_rsa_keys(PUBLIC_KEYS, PRIVATE_KEYS)
    while True:
        try:
            user, address = server.accept()
            print(colored(f"[+] Username: {user} is connected from {address}.", "green"))
            user.send(server_public_key.save_pkcs1("PEM"))
            user_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
            message = rsa.decrypt(user.recv(1024), server_private_key).decode()

            if "/login" in message:
                log, username, password = message.split(" ")
                if log == "/login" and user_login(username, password) == True:
                    user.send(rsa.encrypt('SUCCESS'.encode(), user_public_key))
                else:
                    user.send(rsa.encrypt('Login Failed!'.encode(), user_public_key))
            else:
                user.send(rsa.encrypt('Invalid Command!'.encode(), user_public_key))
            user.close()
        except Exception as e:
            print(colored(f"[-] Error: {e}", "red"))
            user.close()
        finally:
            user.close()

#############################################################################################
# user_login
# @args: username -> user name on the chat
# @args: password -> user password
# @return:
# The systems receives the username and password and logs the user on the server.
##############################################################################################
def user_login(username, password):
    """
    user_login function
    Processes the user login, checks if user is registered
    :param username: User username.
    :param password: User password.
    :return: True if login, False if fails.
    """
    if os.path.exists(USERS_REGISTER):
        with open(USERS_REGISTER, "r") as file:
            users = json.load(file)
    else:
        print("Login data error.")
        return False

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if username not in users or  users[username] != hashed_password:
        print(colored(f"Invalid login credentials.", "red"))
        return False

    print(colored(f"Login successful!", "green"))
    return True

#############################################################################################
# start_register_server
# @args: server_ip -> the IP for the server to listen on
# @args: server_port -> the port for the server to listen on
# @return:
# Starts the server that allows for users to login.
##############################################################################################
def start_register_server(server_ip, server_port):
    """
    start_register_server function
    Start the server to register users.
    :param server_ip: IP where the server receives communications.
    :param server_port: Network port where the server receives communications.
    :return:
    """
    server.bind((server_ip, server_port))
    server.listen()
    print(colored(f"Register server active on-> {server_ip}:{server_port}\n", "green"))
    server_public_key, server_private_key = KeyManager.get_rsa_keys(PUBLIC_KEYS, PRIVATE_KEYS)
    while True:
        try:
            user, address = server.accept()
            print(colored(f"[+] Username: {user} is connected from {address}.", "green"))

            user.send(server_public_key.save_pkcs1("PEM"))
            user_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
            message = rsa.decrypt(user.recv(1024), server_private_key).decode()

            if "/register" in message:
                reg, username, password = message.split(" ")
                print(f"register detected and {reg} in first place")
                if "/register" and register_user(username, password):
                    user.send(rsa.encrypt("SUCCESS".encode(), user_public_key))

                else:
                    user.send(rsa.encrypt("Register Failed!".encode(), user_public_key))

            else:
                user.send(rsa.encrypt("Invalid Command!".encode(), user_public_key))
            user.close()
        except Exception as e:
            print(colored(f"[-] Error: {e}", "red"))
            user.close()
        finally:
            user.close()

###############################################################
#
# Data server
#
###############################################################

def start_data_server(server_ip, server_port):
    """
    start_data_server function
    Start server for data requests
    :param server_ip: IP where the server receives communications.
    :param server_port: Network port where the server receives communications.
    :return:
    """
    server.bind((server_ip, server_port))
    server.listen()
    print(f"Stored Data Server listening on {server_ip}:{server_port}")
    server_public_key, server_private_key =  KeyManager.get_rsa_keys(PUBLIC_KEYS, PRIVATE_KEYS)
    get_stored_data(server_public_key, server_private_key)


###############################################################
#
# Stored_data_commands
#
###############################################################

def get_stored_data(public_key, private_key):
    """
    get_stored_data function
    Gets the user stored messages and returns it to the user.
    :param public_key: Server public key
    :param private_key: Server private key
    :return: List of messages, or feedback if something goes wrong.
    """
    while True:
        try:
            user, address = server.accept()
            print(colored(f"[+] Username: {user} is connected from {address}.", "green"))

            user.send(public_key.save_pkcs1("PEM"))
            user_public_key = rsa.PublicKey.load_pkcs1(user.recv(1024))
            message = rsa.decrypt(user.recv(1024), private_key).decode()

            if "/message_history" in message:
                request, username = message.split(" ")
                message_list = process_messages(username)
                message_history = pickle.dumps(message_list)
                user.sendall(message_history)
            else:
                user.send(rsa.encrypt("Invalid Option.".encode(), user_public_key))
            user.close()
        except Exception as e:
            print(colored(f"Error: {e}", "red"))
            user.close()
        finally:
            user.close()


###############################################################
#
# Process Message History
#
###############################################################

def process_messages(username):
    """
    process_messages function
    Opens the message file for the user, processes the data and returns the list of messages to be sent back.
    :param username: User username.
    :return: List of messages or null if something goes wrong.
    """

    with open(USERS_REGISTER, "r") as file:
        registered_users = json.load(file)

    if username not in registered_users:
        print(colored("Username not found.", "red"))
        return

    if os.path.exists(MESSAGE_LOG+username+".json"):
        with open(MESSAGE_LOG+username+".json", "r") as message_file:
            messages = json.load(message_file)["messages"]
            message_history = []
            for message in messages:
                message_history.append(bytes.fromhex(message))
            return message_history
    else:
        print(colored(f"[-] No message history for {username}.", "red"))
        return

