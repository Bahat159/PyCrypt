import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Asymmetric cryptography is a branch of cryptography where a secret key can be divided into two parts, 
# a public key and a private key. 
# The public key can be given to anyone, trusted or not, 
# while the private key must be kept secret (just like the key in symmetric cryptography).

# Asymmetric cryptography has two primary use cases: 
# authentication and confidentiality. 
# Using asymmetric cryptography, 
# messages can be signed with a private key, 
# and then anyone with the public key is able to verify that the message was created by someone possessing the corresponding private key. 
# This can be combined with a proof of identity system to know what entity (person or group) actually owns that private key, 
# providing authentication.

# Encryption with asymmetric cryptography works in a slightly different way from symmetric encryption. 
# Someone with the public key is able to encrypt a message, providing confidentiality, 
# and then only the person in possession of the private key is able to decrypt it.

class Assymetric_Ed25519_signing():
    def __init__(self):
        self.author         = 'Busari Habibullaah'
        self.description    = 'Ed25519 signing'

    def generate_ed25519_private_key(self):
        private_key = Ed25519PrivateKey.generate()
        return private_key

    def sign_ed25519_(self, ed_generated_private_key, auth_message):
        signature = ed_generated_private_key.sign(auth_message)
        return signature

    def generate_ed25519_public_key(self, ed_generated_private_key):
        public_key = ed_generated_private_key.public_key()
        return public_key

    def sign_and_verify_public_key(self, public_key, signature, auth_message):
        sign_and_verify = public_key.verify(signature, auth_message)
        return sign_and_verify

class Assymetric_X25519PrivateKey():
    def __init__(self):
        self.author         = 'Busari Habibullaah'
        self.description    = 'Ed25519 signing'
        self.object_arg     = ''
    
    def __str__(self):
        return self.object_arg

    def __repr__(self):
        return self.object_arg

    def generate_X25519PrivateKey(self):
        private_key =  X25519PrivateKey.generate()
        self.object_arg = private_key
        return self.object_arg

    def generate_peer_public_key_X25519PrivateKey(self):
        public_key =  X25519PrivateKey.generate().public_key()
        self.object_arg = public_key
        return self.object_arg

    def generate_shared_key(self, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        return shared_key



