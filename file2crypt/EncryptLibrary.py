import os
import sys
import base64
from colorama import init
from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# copyright, Sandcroft Software, 2021.

# Library features 
# encrypt filetypes (exe,pdf,jpg,txt,svg)


# program flow
# generate a new token
# make an encryption key
# encrypt data

init(autoreset=True)

myFile = "./fsm.txt"

def generate_new_token():
    passcode = Fernet.generate_key()
    return passcode

def print_red(message):
    print(f"{Fore.RED}{message}")

def print_success(message):
    print(f"{Back.GREEN}{message}")

def make_new_encryption_key(passcode):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=320000,
    backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passcode))
    return Fernet(key)


def encrypt_data(key_frame,message):
    encrypted_token = key_frame.encrypt(bytes(message,  encoding='utf-8'))
    return encrypted_token

def decrypt_data(key_frame,message):
    decrypted_token = key_frame.decrypt(message)
    return decrypted_token

def file_content_to_encrypt(myFile):
     with open(myFile,'r') as new_content:
        file_content = new_content.read().replace('\r', '')
        return file_content

def show_decrypted_file_content(newKey,myFile):
    if newKey:
        dec_data = decrypt_data(newKey, myFile)
        return dec_data

def show_encrypted_file_content(newKey,myFile):
    if newKey:
        enc_data = encrypt_data(newKey, myFile)
        return enc_data


def encrypt_file_content(newKey, myFile):
    file_content = file_content_to_encrypt(myFile)
    enc_data = encrypt_data(newKey, file_content)
    return enc_data

def decrypt_file_content(newKey, myFile):
    decrypt_me = file_content_to_encrypt(myFile)
    dec_data = decrypt_data(newKey, decrypt_me)
    return dec_data





