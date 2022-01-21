import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

# ANS X9.62 defines methods for digital signature generation and verification using the Elliptic 
# Curve Digital Signature Algorithm (ECDSA).
#
# ECDSA requires that the private/public key pairs used for digital signature generation 
# and verification be generated with respect to a particular set of domain parameters.
#
# Note that while elliptic curve keys can be used for both signing and key exchange, this is bad cryptographic practice. 
# Instead, users should generate separate signing and ECDH keys.

class Elliptic_Curve_Signature_Algorithms():
    def __init__(self):
        self.author             = 'Busari Habibullaah'
        self.gen_private_key    = True
        self.data               = bytes('this is some data I\'d like to sign')
        self.hash               = hashes.SHA256()
    
    def generate_private_key(self):
        if self.gen_private_key:
            private_key = ec.generate_private_key(ec.SECP384R1())
            return private_key
    
    def generate_public_key(self, private_key):
        return private_key.public_key()

    def signature_message(self):
        if self.data:
            signature = private_key.sign(self.data,ec.ECDSA(hashes.SHA256()))
            return signature

    # If your data is too large to be passed in a single call, 
    # you can hash it separately and pass that value using Prehashed.

    def hash_and_sign_large_file_with_private_key(self, private_key, hash_type, data_to_hash, more_data_to_hash = None):
        hasher  = hashes.Hash(hash_type)
        bytes_to_hash = bytes(data_to_hash)
        more_data_to_hash = bytes(more_data_to_hash)
        hasher.update(bytes_to_hash)
        hasher.update(more_data_to_hash)
        digest = hasher.finalize()
        if digest:
            return private_key.sign(digest,ec.ECDSA(utils.Prehashed(self.hash))) 
    

    def hash_and_sign_large_file_with_public_key(self, public_key, signature, hash_type, data_to_hash, more_data_to_hash = None):
        hasher = hashes.Hash(hash_type)
        data_to_has_in_bytes = bytes(data_to_hash)
        more_data_to_hash_in_bytes = bytes(more_data_to_hash)
        hasher.update(data_to_has_in_bytes)
        hasher.update(more_data_to_hash_in_bytes)
        digest = hasher.finalize()
        if digest:
            return public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(self.hash)))


    
