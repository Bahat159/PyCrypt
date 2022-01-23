from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa


# DSA is a legacy algorithm and should generally be 
# avoided in favor of choices like EdDSA using curve25519 or ECDSA.

# DSA is a public-key algorithm for signing messages.

class DSA_Algoirthm:
    def __init__(self):
        self.key_size = int('1024')
        self.data     = bytes("this is some data I'd like to sign")
        self.hash_algorithm = hashes.SHA256()
    
    # Generate Private Key
    def generate_privte_key(self, use_private_key = True):
        if use_private_key:
            private_key = dsa.generate_private_key(key_size=self.key_size,)
        return private_key
    
    # Message Signing
    def signature(self, data, use_signing = True):
        if use_signing:
            signature = private_key.sign(data,self.hash_algorithm)
        return signature
