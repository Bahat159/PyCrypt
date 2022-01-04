import os
import sys
import base64
from colorama import init
from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# copyright, Sandcroft Software, 2021.
# implementing encryption algorithms OCD( Authenticated encryption (AEAD) )

# Library features 
# encrypt filetypes (exe,pdf,jpg,txt,svg)

# crypt letter
# program flow
# generate a new token
# make an encryption key
# encrypt data
# all major variables must accept command from config to change at will

#   BASED ON OCB algo
# OCB is a blockcipher-based mode of operation that simultaneously provides both privacy and authenticity for a user-supplied plaintext
# the algorithm is efficiently realizable by smart cards, FPGAs, and high-speed ASICs

#   ANOTHER RELIABLE METHOD TO ACHIEVE PRIVACY

# In the past, when one wanted a shared-key mechanism providing both privacy and authenticity
# the usual thing to do was to separately encrypt and compute a MAC, using two different keys
#  (The word MAC stands for Message Authentication Code.)

# If one is encrypting and MACing in a conventional way,
# like CTR-mode encryption and the CBC MAC
# the cost for privacy-and-authenticity is going to be twice the cost for privacy alone
# just counting blockcipher calls.
#

#   NOTETHIS 

# The encryption is what buys you privacy and the MAC is what gets you authenticity.
# The cost to get privacy-and-authenticity in this way is about the cost to encrypt (with a privacy-only scheme) plus the cost to MAC.
 
init(autoreset=True)

myFile = "./fsm.txt"
class EncryptWithFernet():
    def __init__(file_name):
        myFile = file_name

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


class HazardousMaterialLayer_AEAD():
    # Authenticated encryption (AEAD)
    # Authenticated encryption with associated data (AEAD) are encryption schemes 
    # which provide both confidentiality and integrity for their ciphertext. 
    # They also support providing integrity for associated data which is not encrypted.
    

    def __init__(self, print_class):
        self.print_class_callback = print_class
        #self.decode  = ""
        #self.cha_cha_key = ""
        self.hazardous_material_layer_data = ["Library alert mode "]

    def encrypt_decrypt_with_ChaCha_algorithm(self):
        data_to_encrypt = ""
        auth_data_but_unencrypted = ""
        key = generate_new_chacha_key_with_class_method_()
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        encrypt = chacha.encrypt(nonce, data_to_encrypt, auth_data_but_unencrypted)
        decrypt = chacha.decrypt(nonce, encrypt, auth_data_but_unencrypted)

    def encrypt_decrypt_with_aesgcm(self, bit_length):
        # bit_length can be 128, 192, or 256-bit key. This must be kept secret.
        # The nonce-based part of the name means that OCB requires a nonce to encrypt each message. 
        # OCB does not require the nonce to be random; a counter, say, will work fine. 
        
        # Unlike some modes, the plaintext provided to OCB can be of any length, 
        # as can the associated data, 
        # and OCB will encrypt the plaintext without padding it to some convenient-length string,
        #  an approach that would yield a longer ciphertext.
        
        data_to_encrypt = ""
        auth_data_but_unencrypted = ""
        key = AESGCM.generate_key(bit_length)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        
        # The associated-data part of the name means that when OCB encrypts a plaintext it can bind it to some other string, 
        # called the associated data, that is authenticated but not encrypted.
        
        encrypt_data = aesgcm.encrypt(nonce, data_to_encrypt, auth_data_but_unencrypted)
        decrypt_data = aesgcm.decrypt(nonce, encrypt_data, auth_data_but_unencrypted)
    

    # OCB solves the problem of nonce-based authenticated-encryption with associated-data (AEAD). 
    # The associated-data part of the name means that when OCB encrypts a plaintext it can bind it to some other string, 
    # called the associated data, that is authenticated but not encrypted.

    # The associated-data part of the name means that when OCB encrypts a plaintext it can bind it to some other string, called the associated data,
    # OCB is a blockcipher-based mode of operation that simultaneously provides both privacy and authenticity for a user-supplied plaintext
    #

    def _generate_new_chacha20Poly1305_key_(self, print_class_callback):
        try:
            algor = 'cryptography.exceptions.UnsupportedAlgorithm'
            from base64 import b64encode
            new_key = ChaCha20Poly1305.generate_key()
            decode = b64encode(new_key).decode()

            #print_class_callback.print_with_format(new_key, decode)
            #print_class_callback.print_format_with_index_number(new_key, decode)

            #print(f'\nchacha20Poly1305 KEY = [{new_key}]', end="\r")
            #print(f'b64decode  = [{decode}]', end=" ")
            return {
                "decode": decode,
                "new_key": new_key,
                }
        except Exception:
            raise UnsupportedAlgorithm('\n{0} not supported'.format(algor),[_Reasons.UNSUPPORTED_HASH, _Reasons.UNSUPPORTED_HASH])
            sys.exit('Exception occured !!!')

class PrintWithFormat():
    def __init__(self):
        self.data    = []
        self.new_key = " MY"
        self.decode  = " DE"

    def print_with_format(self,new_key, decode):
        print_format = "\n New ChaCha key => {} \n Decoded String with Base64() {}\n"
        print(print_format.format(new_key, decode))
    
    def print_format_with_index_number(self,new_key, decode):
        print_format_with_index_number = "\n New ChaCha key => {0} \n Decoded String with Base64() {1}\n"
        print(print_format_with_index_number.format(new_key, decode))

    def print_with_named_index(self, new_key, decode):
        # TODOHERE

        # not working properly 
        # need to be fixed to work with Default Argument Values
        print_with_named_index = "\n New ChaCha key => {new_key} \n Decoded String with Base64() {decode}\n"
        print(print_with_named_index.format(new_key, decode))

    def print_text(message):
        print(f'{message}')
    
    def initiate_module():
        try:
            print_class = PrintWithFormat()
            class_method = HazardousMaterialLayer_AEAD(print_class)
            returned_key = class_method._generate_new_chacha20Poly1305_key_(print_class)
            key = returned_key['new_key']
            decoder = returned_key['decode']

            print('\nNew Key = [{0}]\nBase64decode = [{1}]\n'.format(key, decoder), end=" ")
        except Exception as err:
            print(f'\nException occured in operation ==> {err}')
            sys.exit('App exiting ....')

