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
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# copyright, Sandcroft Software, 2021.
# implementing encryption algorithms OCD( Authenticated encryption (AEAD) )

# Library features 
# encrypt filetypes (exe,pdf,jpg,txt,svg)

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
        self.key_length = int('32')
        self.iterations = int('320000')
        self.salt_length = os.urandom(int('16'))
        self.encoding_type = hashes.SHA256()
    
    def __repr__(self):
        return self

    def generate_new_token(self, use_generate_token = True):
        if use_generate_token:
            passcode = Fernet.generate_key()
        return passcode

    def make_new_encryption_key(passcode, use_generate_key = True):
        if use_generate_key:
            kdf = PBKDF2HMAC(algorithm=self.encoding_type,length=self.key_length,salt=self.salt_length,iterations=self.iterations,backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(passcode))
        return Fernet(key)


    def encrypt_data(key_frame,message):
        encrypted_token = key_frame.encrypt(bytes(message,  encoding='utf8'))
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


class HazardousMaterialLayer_AEAD_ChaCha20Poly1305():
    # Authenticated encryption (AEAD)
    # Authenticated encryption with associated data (AEAD) are encryption schemes 
    # which provide both confidentiality and integrity for their ciphertext. 
    # They also support providing integrity for associated data which is not encrypted.
    
    # data type to encrypt : .exe, .pdf, .txt file extension. to begin with
    # associated data: bind to data, unencrypted
        
    # Unlike some modes, the plaintext provided to OCB can be of any length
    # as can the associated data
    # and OCB will encrypt the plaintext without padding it to some convenient-length string
    #  an approach that would yield a longer ciphertext.

    def __init__(self, print_class, associated_data):
        self.print_class_callback          = print_class
        self.associated_data_param         = associated_data
        self.hazardous_material_layer_data = [" Library alert mode "]
        self.description                   = "OCB AEAD ChaCha Cipher Encryption Implementation"
        self.author                        = "Busari Habibullaah"
        self.nonce                         = os.urandom(int('12'))
    
    def __repr__(self):
        return self

    def _generate_new_chacha20Poly1305_key_(self):
        # Securely generates a random ChaCha20Poly1305 key.
        # Returns bytes A 32 byte key.
        try:
            algor = 'cryptography.exceptions.UnsupportedAlgorithm'
            from base64 import b64encode
            new_key = ChaCha20Poly1305.generate_key()
            decode = b64encode(new_key).decode()

            return {
                "decode": decode,
                "new_key": new_key,
                }
        except Exception:
            raise UnsupportedAlgorithm('\n{0} not supported'.format(algor),[_Reasons.UNSUPPORTED_HASH, _Reasons.UNSUPPORTED_HASH])
            sys.exit('Exception occured !!!')

    def encrypt_with_ChaCha_algorithm(self, nonce, encrypt_data, asssociated_data_to_encrypt):
        key = _generate_new_chacha20Poly1305_key_()
        data_to_encrypt = encrypt_data
        associated_data = asssociated_data_to_encrypt
        chacha = ChaCha20Poly1305(key)
        try:
            encrypt = chacha.encrypt(nonce, data_to_encrypt, associated_data)
        except OverflowError as overflow:
            sys.exit(f'Overflow Error encounterd  ==> {overflow}')
        return encrypt
    
    def decrypt_with_ChaCha_algorithm(self, nonce, key_to_decrypt, encrypted_data, asssociated_data_to_encrypt):
        associated_data = asssociated_data_to_encrypt
        encrypt = encrypted_data
        chacha = ChaCha20Poly1305(key_to_decrypt)
        algor = 'cryptography.exceptions.InvalidTag'
        try:
            decrypt = chacha.decrypt(nonce, encrypt, associated_data)
        except Exception:
            raise InvalidTag('\n{0} an authenticated encryption tag fails to verify during decryption'.format(algor))
        return decrypt


class HazardousMaterialLayer_AEAD_AESGCM():

    # OCB solves the problem of nonce-based authenticated-encryption with associated-data (AEAD) 
    # The associated-data part of the name means that when OCB encrypts
    # a plaintext it can bind it to some other string, 
    # called the associated data, that is authenticated but not encrypted.

    # The associated-data part of the name means that when OCB encrypts a plaintext
    # it can bind it to some other string, called the associated data,
    # OCB is a blockcipher-based mode of operation that simultaneously provides 
    # both privacy and authenticity for a user-supplied plaintext

    def __init__():
        self.description                   = "OCB AEAD AESGCM Cipher Encryption Implementation"
        self.author                        = "Busari Habibullaah"
        self.nonce                         = os.urandom(int('12'))
        self.bit_length                    = int('256')
    
    def __repr__(self):
        return self

    def generate_aesgcm_key(self, bit_length):
        # bit_length can be 128, 192, or 256-bit key. This must be kept secret
        key = AESGCM.generate_key(bit_length)
        aesgcm_generated_key = AESGCM(key)
        return aesgcm_generated_key

    def encrypt_with_aesgcm(self, data, associated_data_param):

        # data type to encrypt : .exe, .pdf, .txt file extension. to begin with
        # associated data: bind to data, unencrypted
        
        # Unlike some modes, the plaintext provided to OCB can be of any length
        # as can the associated data
        # and OCB will encrypt the plaintext without padding it to some convenient-length string
        #  an approach that would yield a longer ciphertext.
        aesgcm_key = generate_aesgcm_key(self.bit_length)

        # OCB does not require the nonce to be random; a counter, say, will work fine
        # The nonce-based part of the name means that OCB requires a nonce to encrypt each message
        nonce = self.nonce
        
        # The associated-data part of the name means that when OCB encrypts a plaintext 
        # it can bind it to some other string 
        # called the associated data, that is authenticated but not encrypted.
        associated_data = associated_data_param
        data_to_encrypt = data
        try:
            encrypt_data = aesgcm_key.encrypt(nonce, data_to_encrypt, associated_data)
        except OverflowError as overflow:
            sys.exit(f'Overflow Error encounterd  ==> {overflow}')    
        return encrypt_data

    def decrypt_aesgcm_data(self, nonce, encrypt_data, associated_data):
        algor = 'cryptography.exceptions.InvalidTag'
        try:
            decrypt_data = aesgcm_key.decrypt(nonce, encrypt_data, associated_data)
        except Exception:
            raise InvalidTag('\n{0} an authenticated encryption tag fails to verify during decryption'.format(algor))
        return decrypt_data 


class HazardousMaterialLayer_AEAD_AESOCB3():
    def __init__(self):
        self.description                   = "OCB AEAD AESOCB3 Cipher Encryption Implementation"
        self.author                        = "Busari Habibullaah"
        self.nonce                         = os.urandom(12)
        self.bit_length                    = int('256')
    

    def __repr__(self):
        return self

    def generate_aesocb3_key(self):
        key = AESOCB3.generate_key(self.bit_length)
        aesocb3_key = AESOCB3(key)
        return aesocb3_key

    def encrypt_aesocb3_data(self, aesocb_generated_key, encrypt_data, associated_data):
        nonce = self.nonce
        associated_data_param = associated_data
        encrypt_data = aesocb_generated_key.encrypt(nonce, encrypt_data, associated_data_param)
        return encrypt_aesocb_data

    def decrypt_aesocb3_data(self, aesocb_generated_key, encrypt_data, associated_data):
        nonce = self.nonce
        decrypt_aesocb_data = aesocb_generated_key.decrypt(nonce, encrypt_data, associated_data)
        return decrypt_aesocb_data

class HazardousMaterialLayer_AEAD_AESCCM():
    def __init__(self):
        self.description                   = "OCB AEAD AESCCM Cipher Encryption Implementation"
        self.author                        = "Busari Habibullaah"
        self.nonce                         = os.urandom(12)
        self.bit_length                    = int('256')         # key length (128, 192, 256 bit-key)
    
    def __repr__(self):
        return self

    def generate_aesocb3_key(self):
        key = AESCCM.generate_key(self.bit_length)
        aesccm_key = AESCCM(key)
        return aesccm_key
    
    def encrypt_aesccm_data(self, aesccm_generated_key, encrypt_data, associated_data):
        nonce = self.nonce
        associated_data_param = associated_data
        encrypt_data = aesccm_generated_key.encrypt(nonce, encrypt_data, associated_data_param)
        return aesccm_generated_key

    def decrypt_aesocb3_data(self, aesccm_generated_key, encrypt_data, associated_data):
        nonce = self.nonce
        decrypt_aesccb_data = aesccm_generated_key.decrypt(nonce, encrypt_data, associated_data)
        return decrypt_aesccb_data


class PrintWithFormat():
    def __init__(self):
        self.data    = []
        self.new_key = str("MY")
        self.decode  = str("DE")
    
    def __repr__(self):
        return self

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

