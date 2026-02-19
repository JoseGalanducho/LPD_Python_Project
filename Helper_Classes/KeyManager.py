#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# KeyManager, this class manages encription keys
#############################################################################################
import os

#imports
import rsa

#constant variables

#############################################################################################
# get_server_keys
# @return:
# Reads the private and public key, if there is no private or public key,
# it will generate new ones and save them.
##############################################################################################
def get_rsa_keys(public_keys_file, private_keys_file):

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
def get_user_keys(username, public_keys_file, private_keys_file):

    user_public_key, user_private_key  = rsa.newkeys(1024)

    if os.path.exists(public_keys_file + username + ".pem"):
        with open(public_keys_file + username + ".pem", "rb") as file:
            user_public_key = rsa.PublicKey.load_pkcs1(file.read())
    else:
        with open(public_keys_file + username + ".pem", "wb") as file:
            file.write(user_public_key.save_pkcs1("PEM"))

    if os.path.exists(private_keys_file + username + ".pem"):
        with open(private_keys_file + username + ".pem", "rb") as file:
            user_private_key = rsa.PrivateKey.load_pkcs1(file.read())
    else:
        with open(private_keys_file + username + ".pem", "wb") as file:
            file.write(user_private_key.save_pkcs1("PEM"))

    return user_public_key, user_private_key