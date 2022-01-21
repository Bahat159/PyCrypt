import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils

# ANS X9.62 defines methods for digital signature generation and verification using the Elliptic 
# Curve Digital Signature Algorithm (ECDSA).
#
# ECDSA requires that the private/public key pairs used for digital signature generation 
# and verification be generated with respect to a particular set of domain parameters.
#
# Note that while elliptic curve keys can be used for both signing and key exchange, this is bad cryptographic practice. 
# Instead, users should generate separate signing and ECDH keys.
#
# ECDSA keys shall not be used for any other purpose (e.g., key establishment)

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


# This example does not give forward secrecy and is only provided as a demonstration of the 
# basic Diffie-Hellman construction. 
# For real world applications always use the ephemeral form described after this example.

class Elliptic_Curve_Key_Exchange_algorithm():
    def __init__(self):
        self.exchange_algorthim = True
        self.hash_algorithm     = hashes.SHA256()
        self.key_length         = 32   # can be of any length (e.g, 1024, 2048, 256 and so on)
        self.data_to_encode     = bytes('handshake data')
    
    def generate_server_private_key(self, generate_server_private_key = True):
        if generate_server_private_key:
            server_private_key = ec.generate_private_key(ec.SECP384R1())
        return server_private_key
    
    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though.

    def generate_peer_private_key(self, generate_peer_private_key = True):
        if generate_peer_private_key:
            peer_private_key = ec.generate_private_key(ec.SECP384R1())
        return peer_private_key
    
    def shared_key_exchange(self, server_private_key, peer_private_key):
        if server_private_key:
            shared_key = server_private_key.exchange(ec.ECDH(), peer_private_key.public_key())
        return shared_key
    
    # Perform key derivation.

    def perform_key_derivation(self, shared_key):
        if shared_key:
            derived_key = HKDF(algorithm=self.hash_algorithm,length=self.key_length,salt=None,info=self.data_to_encode,).derive(shared_key)
        return derived_key
    
    # And now we can demonstrate that the handshake performed in the
    # opposite direction gives the same final value
    
    def generate_same_shared_key_with_peer_private_key(self, peer_private_key, server_private_key):
        if peer_private_key and server_private_key:
            same_shared_key = peer_private_key.exchange(ec.ECDH(), server_private_key.public_key())
        return same_shared_key
    

    # Perform key derivation.

    def perform_key_derivation_with_same_dervied_key(self, same_shared_key):
        if same_shared_key:
            same_derived_key = HKDF(algorithm=self.hash_algorithm,length=self.key_length,salt=None,info=self.data_to_encode,).derive(same_shared_key)
        return same_derived_key

    def check_key_derivation(self, derived_key, same_derived_key):
        if derived_key == same_derived_key:
            return True 
        else:
            return False


# ECDHE (or EECDH), the ephemeral form of this exchange, 
# is strongly preferred over simple ECDH and provides forward secrecy when used. 
# You must generate a new private key using generate_private_key() 
# for each exchange() when performing an ECDHE key exchange. An example of the ephemeral form:

class ECDHE_key_Exchange_Ephemeral_Form:
    def __init__(self):
        self.ephemeral      = True
        self.key_alogrithm  = hashes.SHA256()
        self.key_length     = 32
        self.handshake_data = bytes('Handshake Data')
    
    # Generate a private key for use in the exchange.
    def generate_private_key(self):
        if self.ephemeral:
            private_key = ec.generate_private_key(ec.SECP384R1())
        return private_key
    
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key
    # and get a public key from that.
    def generate_peer_public_key(self):
        peer_public_key = ec.generate_private_key(ec.SECP384R1()).public_key()
        return peer_public_key
    
    def generate_shared_key(self, private_key):
        if private_key:
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return private_key
    
    # Perform key derivation.
    def perform_key_derivation(self, shared_key):
        if shared_key:
            derived_key = HKDF(algorithm=self.key_alogrithm,length=self.key_length,salt=None,info=self.handshake_data,).derive(shared_key)
        return derived_key
    
    # For the next handshake we MUST generate another private key.
    def generate_handshake_private_key(self):
        private_key_2 = ec.generate_private_key(ec.SECP384R1())
        return private_key_2
    
    def generate_handshake_peer_public_key(self, handshake_peer_public_key = True):
        if handshake_peer_public_key:
            peer_public_key_2 = ec.generate_private_key(ec.SECP384R1()).public_key()
        return peer_public_key_2
    
    def generate_handshake_shared_key(self, peer_public_key_2, handshale_shared_key = True):
        if handshale_shared_key:
            shared_key_2 = private_key_2.exchange(ec.ECDH(), peer_public_key_2)
        return shared_key_2
    
    def generate_handshake_derived_key(self, shared_key_2):
        if shared_key_2:
            derived_key_2 = HKDF(algorithm=self.key_alogrithm,length=self.key_length,salt=None,info=self.handshake_data,).derive(shared_key_2)
        return shared_key_2
