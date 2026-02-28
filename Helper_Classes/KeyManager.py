#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# KeyManager, this class manages encription keys
#############################################################################################
import os

#imports
import rsa

#constant variables
USER_PRIVATE_KEYS = "Secure_Messaging/rsa_secret_"
USER_PUBLIC_KEYS = "Secure_Messaging/rsa_public_"

#############################################################################################
# get_server_keys
# @return:
# Reads the private and public key, if there is no private or public key,
# it will generate new ones and save them.
##############################################################################################
def get_rsa_keys(public_keys_file, private_keys_file):
    """
    get_rsa_keys function
    Reads, or generates rsa keys for the servers.
    :param public_keys_file: Filepath to save the public keys.
    :param private_keys_file: Filepath to save the private keys.
    :return:
    """
    public_key, private_key = rsa.newkeys(1024)

    if not os.path.exists(public_keys_file):
        with open(public_keys_file, "wb") as file:
            file.write(public_key.save_pkcs1("PEM"))
    else:
        with open(public_keys_file, "rb") as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read())

    if not os.path.exists(private_keys_file):
        with open(private_keys_file, "wb") as file:
            file.write(private_key.save_pkcs1("PEM"))
    else:
        with open(private_keys_file, "rb") as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read())

    return public_key, private_key

#############################################################################################
# get_user_keys
# @args: username -> user username for the server
# @return:
# Generates a pair of rsa keys or reads the keys if they already exists
##############################################################################################
def get_user_keys(username):
    """
    get_user_keys function
    Reads user rsa keys if available, otherwise generates rsa keys.
    :param username: User username.
    :return:
    """
    user_public_key, user_private_key  = rsa.newkeys(1024)

    if os.path.exists(USER_PUBLIC_KEYS + username + ".pem"):
        with open(USER_PUBLIC_KEYS + username + ".pem", "rb") as file:
            user_public_key = rsa.PublicKey.load_pkcs1(file.read())
    else:
        with open(USER_PUBLIC_KEYS + username + ".pem", "wb") as file:
            file.write(user_public_key.save_pkcs1("PEM"))

    if os.path.exists(USER_PRIVATE_KEYS + username + ".pem"):
        with open(USER_PRIVATE_KEYS + username + ".pem", "rb") as file:
            user_private_key = rsa.PrivateKey.load_pkcs1(file.read())
    else:
        with open(USER_PRIVATE_KEYS + username + ".pem", "wb") as file:
            file.write(user_private_key.save_pkcs1("PEM"))

    return user_public_key, user_private_key