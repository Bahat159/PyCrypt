import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Symmetric encryption
#
# Symmetric encryption is a way to encrypt or hide the contents 
# of material where the sender and receiver both use the same secret key. 
# Note that symmetric encryption is not sufficient for most applications 
# because it only provides secrecy but not authenticity. 
# That means an attacker can’t see the message but an attacker 
# can create bogus messages and force the application to decrypt them. 
# In many contexts, a lack of authentication on encrypted messages can result in a loss of secrecy as well.
#
# For this reason it is strongly recommended to combine encryption 
# with a message authentication code, such as HMAC, 
# in an “encrypt-then-MAC” formulation as described by Colin Percival. 
# cryptography includes a recipe named Fernet (symmetric encryption) 
# that does this for you. To minimize the risk of security issues 
# you should evaluate Fernet to see if it fits your needs before implementing anything using this module.

# Example Usage
#class_object = symmertic_Encryption()
#encrypt = class_object.do_AES_encryption()
#decrypt = class_object.do_AES_decryption(encrypt)
#
#print(encrypt)
# b'\x19\x0c\x93\x1c\xffx\x8d*zv\xe7\x97\x12\xb3\xed\xad'
#
#print(decrypt)
# b'a secret message'


class symmertic_Encryption:
    # Cipher objects combine an algorithm such as AES with a mode like CBC or CTR. 
    # A simple example of encrypting and then decrypting content with AES is:

    def __init__(self):
        self.chahcha_nonce = os.urandom(int('16'))
        self.key_length = os.urandom(int('32'))  # (32, 128, 192, 156)
        self.key_iv     = os.urandom(int('16'))
        self.secret_message = bytes("a secret message", encoding = "utf8")
        self.AES_cipher     = Cipher(algorithms.AES(self.key_length), modes.CBC(self.key_iv))
    
    def __repr__(self):
        return self
    
    def do_AES_encryption(self):
        encryptor = self.AES_cipher.encryptor()
        ct = encryptor.update(self.secret_message) + encryptor.finalize()
        return ct
    
    def do_AES_decryption(self, ct):
        decryptor = self.AES_cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()
    

    # ChaCha Algorithm

    def do_chacha_encryption(self, key, use_chacha_encryptor = True):
        if use_chacha_encryptor:
            algorithm = algorithms.ChaCha20(key, self.chahcha_nonce)
            cipher = Cipher(algorithm, mode=None)
            encryptor = cipher.encryptor()
            ct = encryptor.update(self.secret_message)
        return ct
    
    def do_chacha_decryption(self, ct, use_chacha_decryptor = True):
        if use_chacha_decryptor:
            algorithm = algorithms.ChaCha20(key, self.chahcha_nonce)
            cipher = Cipher(algorithm, mode=None)
            decryptor = cipher.decryptor()
        return decryptor.update(ct)
