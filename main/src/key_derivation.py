import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

# PBKDF2 (Password Based Key Derivation Function 2) is typically used 
# for deriving a cryptographic key from a password. 
# It may also be used for key storage, 
# but an alternate key storage KDF such as Scrypt is generally considered a better solution.

# Basic Usage
# myclass_obj = Key_derivation()
# my_random_salt = myclass_obj.genreate_random_salts()
# print(my_random_salt)
# output_data = myclass_obj.derive_key(my_random_salt)
# print(output_data)
# final_report = myclass_obj.verfiy_derived_key(my_random_salt, output_data)
# print(final_report)
#
#
# Salts should be randomly generated
class Key_derivation:
    def __init__(self):
        self.salt_length  = int('128')
        self.encode_type  = hashes.SHA256()
        self.key_length   = int('32')
        self.iteration    = int('100000')
        self.key_password = bytes('my great password', encoding="utf8")

    
    # Salts should be randomly generated
    def genreate_random_salts(self):
        salt = os.urandom(self.salt_length)
        return salt
    
    def derive_key(self, salt):
        kdf = PBKDF2HMAC(algorithm=self.encode_type,length=self.key_length,salt=salt,iterations=self.iteration)
        if kdf: 
            key = kdf.derive(self.key_password)
        return key
    
    def verfiy_derived_key(self, salt, key):
        kdf = PBKDF2HMAC(algorithm=self.encode_type,length=self.key_length,salt=salt,iterations=self.iteration)
        if kdf:
            verified_key = kdf.verify(self.key_password, key)
        return verified_key


# Scrypt is a KDF designed for password storage by Colin Percival 
# to be resistant against hardware-assisted attackers 
# by having a tunable memory cost. It is described in RFC 7914.
#
# This class conforms to the KeyDerivationFunction interface.

class Scrypt:
    def __init__(self):
        self.salt_length  = int('128')
        self.key_length   = int('32')
        self.cpu_cost_parameter  = int('2**14')
        self.block_size          = int('8')
        self.parallel_parameter  = int('1')
        self.my_password         = bytes('my great password', encoding="utf8")
    
    def generate_random_salt(self, use_random_salt = True):
        if use_random_salt:
            salt = os.urandom(self.salt_length)
        return salt
    
    def generate_kdf(self, use_derive_key = True):
        if use_derive_key:
            kdf = Scrypt(salt=salt,length=self.key_length,n=self.cpu_cost_parameter,r=self.block_size,p=self.parallel_parameter)
        return kdf
    
    def generte_key(self, kdf):
        if kdf:
            key = kdf.derive(self.my_password)
        return key
    
    def verify_key(self, kdf, key):
        return kdf.verify(self.my_password, key)


# ConcatKDF
#
# ConcatKDFHash (Concatenation Key Derivation Function) 
# is defined by the NIST Special Publication NIST SP 800-56Ar2 document, 
# to be used to derive keys for use after a Key Exchange negotiation operation.

class Fixed_cost_algorithms:
    def __init__(self):
        self.key_length    = int('32')
        self.input_key     = bytes("input key", encoding="utf8")
        self.other_info    = bytes("concatkdf-example", encoding="utf8")
        self.encoding_type = hashes.SHA256()

    
    def ckdf(self, use_ckdf = True):
        if use_ckdf:
            ckdf = ConcatKDFHash(algorithm=self.encoding_type,length=self.key_length,otherinfo= self.other_info)
        return ckdf
    
    def derive_key(self, ckdf, use_derive_key = True):
        if use_derive_key:
            key = ckdf.derive(self.input_key)
        return key
    
    def second_ckdf(self, use_second_ckdf = True):
        if use_second_ckdf:
            ckdf = ConcatKDFHash(algorithm=self.encoding_type,length=self.key_length,otherinfo=self.other_info)
        return ckdf
    
    def verify_ckdf_key_data(self, ckdf, key, use_verify_ckdf_key = True):
        if use_verify_ckdf_key:
            return ckdf.verify(self.input_key, key)


