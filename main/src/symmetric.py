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
#
# class_object = symmertic()
# encrypt = class_object.do_encryption()
# decrypt = class_object.do_decryption(encrypt)
#
# print(encrypt)
#b'\xf2\x93\x14\xc4:\xe4\xb8\xc6\xabzP\x8e\xca\x81(_'
#
# print(decrypt)
# b'a secret message'


class symmertic:
    # Cipher objects combine an algorithm such as AES with a mode like CBC or CTR. 
    # A simple example of encrypting and then decrypting content with AES is:

    def __init__(self):
        self.key_length = os.urandom(int('32'))  # (32, 128, 192, 156)
        self.key_iv     = os.urandom(int('16'))
        self.secret_message = bytes("a secret message", encoding = "utf8")
        self.cipher     = Cipher(algorithms.AES(self.key_length), modes.CBC(self.key_iv))
    
    def __repr__(self):
        return self
    
    def do_encryption(self):
        encryptor = self.cipher.encryptor()
        ct = encryptor.update(self.secret_message) + encryptor.finalize()
        return ct
    
    def do_decryption(self, ct):
        decryptor = self.cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()
        

