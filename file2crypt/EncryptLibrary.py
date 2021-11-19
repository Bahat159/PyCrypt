import os
import sys
import base64
from colorama import init
from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

message = """Secret messaNge to encrypt I can pass anything i want to encrypt here Scenario
Two colleagues in an organisation, Alice and Bob, work at physically distant locations. They need to share a large file (at least 10 MB). This file is extremely sensitive and should not be shared with anyone but themselves. No other members of the organisation should be able to access the document nor should persons outside the organisation. Furthermore, the medium that they will use to send the file, or any other additional data, is not secure. A relatively secure channel, such as a telephone call or letter, is available to distribute a short pass phrase of no more than 25 characters. No other secure channel is available for distribution of sensitive data, such as private cryptographic keys.
Objectives
You need to create 2 programs, which will satisfy the scenario described above:
One program should encrypt the file so that it can be sent securely.
Another program should decrypt the ciphertext received.
You must carefully consider which cryptographic methods and algorithms that you will use to implement the scenario.
Some questions you should consider are:
What cipher is appropriate for encrypting the file?
How will any encryption keys be shared between Alice and Bob securely?
How can encryption keys be certified as genuine?
You must also prepare a 500-word report in which you justify your cryptographic design choices with regard to the requirements of the above scenario. This should only cover the use of cryptography in your application. Your rationale should address the following questions:
What security services does your solution provide?
What cryptographic algorithm has been used to encrypt the data? What cipher modes, if applicable, have you used? Why is this algorithm appropriate to the task?
What other cryptographic algorithms have been used in your application? Again, why are these algorithms appropriately used in your application.
What are the key lengths for cryptographic keys? Why are these key lengths appropriate?
Note that you must identify the cryptographic algorithms used in your software. If you are using a freely available library, you must perform some research to determine the cryptographic algorithms and key lengths the library has implemented.
Software."""

newToken = generate_new_token()
newKey = make_new_encryption_key(newToken)
enc_data = encrypt_data(newKey, message)

def show_decrypt_message_content():
    if newKey:
        dec_data = decrypt_data(newKey, enc_data)
        return dec_data

def show_encrypted_message_content():
    if newKey:
        enc_data = encrypt_data(newKey, message)
        return enc_data


def read_with_file(myFile):
    with open(myFile,'r') as new_content:
        file_content = new_content.read().replace('\r', '')
        enc_data = encrypt_data(newKey, file_content)
        return enc_data

decrypt_me = read_with_file(myFile)

def use_decrypt_with_file():
    dec_data = decrypt_data(newKey, decrypt_me)
    return dec_data






