from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils



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
    
    # Generate Public Key
    def generate_public_key(self, private_key, use_public_key = True):
        if use_public_key:
            public_key = private_key.public_key()
        return public_key
    
    # Message Signing
    def signature(self, data, use_signing = True):
        if use_signing:
            signature = private_key.sign(data,self.hash_algorithm)
        return signature
    

    def sign_big_data(self, private_key, data, use_big_data = True):
        if use_big_data:
            chosen_hash = self.hash_algorithm
            hasher = hashes.Hash(chosen_hash)
            hasher.update(data)
            hasher.update(data)
            digest = hasher.finalize()
            sig = private_key.sign(digest,utils.Prehashed(chosen_hash))
        return sig
    
    # Verification
    def data_verification(self, public_key, signature, data, use_verification = True):
        if use_verification:
            public_key.verify(signature, data, self.hash_algorithm)
        return public_key
    
