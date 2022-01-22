from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# For security and performance reasons we suggest using ECDH instead of DH where possible.
# Diffie-Hellman key exchange (D–H) is a method that allows two parties to 
# jointly agree on a shared secret using an insecure channel.
#
# This example does not give forward secrecy and is only provided 
# as a demonstration of the basic Diffie-Hellman construction. 
#
# For real world applications always use the ephemeral form described after this example.

class Diffie_Hellman_key_exchange:
    def __init__(self):
        self.key_size  = int('2048')
        self.generator = int('2')
        self.key_length  = int('32')
        self.algorithm_type = hashes.SHA256()
        self.handshake_data = bytes('handshake data')
    
    # Generate some parameters. These can be reused.
    def generate_parameter(self, generate_cipher_parameter True):
        if generate_cipher_parameter:
            parameters = dh.generate_parameters(generator=self.generator, key_size=self.key_size)
        return parameters
    
    # Generate a private key for use in the exchange.
    def generate_server_private_key(self, parameters, generate_private_key = True):
        if generate_private_key:
            server_private_key = parameters.generate_private_key()
        reutrn server_private_key
    
    def generate_peer_private_key(self, parameters, use_peer_private_key = True):
        if use_peer_private_key:
            peer_private_key = parameters.generate_private_key()
        return peer_private_key

    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though. Note that in
    # a DH handshake both peers must agree on a common set of parameters.


    def generate_private_shared_key(self, peer_private_key, server_private_key, use_server_key = True):
        if server_private_key:
            shared_key = server_private_key.exchange(peer_private_key.public_key())
        return shared_key
    
    # Perform key derivation.

    def perform_key_derivation(self, shared_key, use_shared_key = True):
        if use_shared_key:
            derived_key = HKDF(algorithm=self.algorithm_type,length=self.key_length,salt=None,info=self.handshake_data,).derive(shared_key)
        return derived_key
    
    # And now we can demonstrate that the handshake performed in the
    # opposite direction gives the same final value

    def perform_data_handshake_with_key(self, peer_private_key, server_private_key, same_shared_key = True):
        if same_shared_key:
            same_shared_key = peer_private_key.exchange(server_private_key.public_key())
        return same_shared_key
    
    def perform_handshake_with_encrypt_algorithm(self, same_shared_key):
        same_derived_key = HKDF(algorithm=self.algorithm_type,length=self.key_length,salt=None,info=self.handshake_data,).derive(same_shared_key)
        return same_derived_key

    def verfiy_data_exchange(self, derived_key, same_derived_key):
        if derived_key and same_derived_key:
            if derived_key == same_derived_key:
                return True


class Diffie_Hellman_key_exchange_Ephemeral_Form:
    def __init__(self):
        self.key_size  = int('2048')
        self.generator = int('2')
    
    # Generate some parameters. These can be reused.

    def generate_parameters(self, use_parameters = True):
        if use_parameters:
            parameters = dh.generate_parameters(generator=self.generator, key_size=self.key_size)
        return parameters
    
    # Generate a private key for use in the exchange.

    def generate_server_private_key(self, parameters, use_server_private_key = True):
        if use_server_private_key:
            server_private_key = parameters.generate_private_key()
        return server_private_key
