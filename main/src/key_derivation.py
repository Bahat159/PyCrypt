import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import (CounterLocation, KBKDFHMAC, KBKDFCMAC, Mode)


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


# Warning
#
# ConcatKDFHMAC should not be used for password storage.
#
# Similar to ConcatKFDHash but uses an HMAC function instead.

class ConcatKDFHMAC:
    def __init__(self):
        self.salt          = os.urandom(int('16'))
        self.encoding_type = hashes.SHA256()
        self.salt_length   = int('32')
        self.input_key     = bytes("input key", encoding="utf8")
        self.otherinfo     = bytes("concatkdf-example", encoding="utf8")
    
    def generate_cdkf(self, use_cdkf = True):
        if use_cdkf:
            ckdf = ConcatKDFHMAC(algorithm=self.encoding_type,length=self.salt_length,salt=salt,otherinfo=self.otherinfo)
        return cdkf
    

    def generate_key(self, ckdf, use_generate_key = True):
        if use_generate_key:
            key = ckdf.derive(self.input_key)
        return key
    
    def second_ckdf(self, use_second_ckdf = True):
        if use_second_ckdf:
            ckdf = ConcatKDFHMAC(algorithm=self.encoding_type,length=self.salt_length,salt=salt,otherinfo=self.otherinfo)
        return ckdf
    
    def verfiy_key(self, key, use_verify_key = True):
        if use_verify_key:
            return ckdf.verify(self.input_key, key)

# HKDF (HMAC-based Extract-and-Expand Key Derivation Function) 
# is suitable for deriving keys of a fixed size used for other cryptographic operations.
#
# Warning
# HKDF should not be used for password storage.

class HKDF:
    def __init__(self):
        self.salt = os.urandom(int('16'))
        self.salt_length = int('32')  # 255 * (algorithm.digest_size // 8)
        self.encoding_type = hashes.SHA256()
        self.info = bytes("hkdf-example", encoding = "utf8")
        self.input_key = bytes("input key",encoding="utf8")
    
    def generate_hkdf(self, use_hkdf = True):
        if use_hkdf:
            hkdf = HKDF(algorithm=self.encoding_type,length=self.salt_length,salt=self.salt,info=self.info)
        return hkdf
    
    def generate_key(self, hkdf, use_generate_key = True):
        if use_generate_key:
            key = hkdf.derive(self.input_key)
        return key
    
    def second_hkdf(self, use_second_hkdf = True):
        if use_second_hkdf:
            hkdf = HKDF(algorithm=self.encoding_type,length=self.salt_length,salt=self.salt,info=self.info)
        return hkdf
    
    def verify_salting(self, hkdf, key, use_verify_salt = True):
        if use_verify_salt:
            return hkdf.verify(self.input_key, key)
    

# HKDF consists of two stages, extract and expand. 
# This class exposes an expand only version of HKDF that is 
# suitable when the key material is already cryptographically strong.
#
# Warning
#
# HKDFExpand should only be used if the key material is cryptographically strong. 
# You should use HKDF if you are unsure.  

class HKDFExpand:
    def __init__(self):
        self.salt_length = int('32')  # 255 * (algorithm.digest_size // 8).
        self.info = bytes("hkdf-example", enconding="utf8")
        self.key_material = os.urandom(int('16'))
        self.encoding_type = hashes.SHA256()
    
    def generate_hkdf_expand(self, use_hkdf_expand = True):
        if use_hkdf_expand:
            hkdf_expand = HKDFExpand(algorithm=self.encoding_type,length=self.salt_length,info=self.info)
        return hkdf_expand
    
    def generate_derive_key(self, use_derive_key = True):
        if use_derive_key:
            key = hkdf.derive(self.key_material)
        return key
    
    def second_hkdf_expand(self, use_second_hkdf = True):
        if use_second_hkdf:
            second_hkdf = HKDFExpand(algorithm=self.encoding_type,length=self.salt_length,info=self.info)
        return second_hkdf
    
    def verify_hkdf_expand(self, hkdf, key, use_verify_hkdf_expand = True):
        if use_verify_hkdf_expand:
            return hkdf.verify(self.key_material, key)


# KBKDF (Key Based Key Derivation Function) is defined by the NIST SP 800-108 document, 
# to be used to derive additional keys from a key that 
# has been established through an automated key-establishment scheme.
#
# Warning
# KBKDFHMAC should not be used for password storage.

class KBKDF:
    def __init__(self):
        self.label = bytes("KBKDF HMAC Label", encoding = "utf8")
        self.context = bytes("KBKDF HMAC Context",encoding="utf8")
        self.encoding_type = hashes.SHA256()
        self.salt_length = int('32')
        self.input_key = bytes("input key", encoding="utf8")
        self.length_of_binary_representation = int('4')
        self.binary_representation_length = int('4')
    
    def generate_kbkdf(self, use_kbkdf = True):
        if use_kbkdf:
            kdf = KBKDFHMAC(algorithm=self.encoding_type,mode=Mode.CounterMode,length=self.salt_length,rlen=self.length_of_binary_representation,llen=self.binary_representation_length,location=CounterLocation.BeforeFixed,label=self.label,context=self.context,fixed=None)
        return kdf
    
    def generate_key(self, kdf, use_generate_key = True):
        if use_generate_key:
            key = kdf.derive(self.input_key)
        return key
    
    def second_kbkdf(self, use_second_kdkdf = True):
        if use_second_kdkdf:
            second_kdf = KBKDFHMAC(algorithm=hashes.SHA256(),mode=Mode.CounterMode,length=self.salt_length,rlen=self.length_of_binary_representation,llen=self.binary_representation_length,location=CounterLocation.BeforeFixed,label=self.label,context=self.context,fixed=None,)
        return second_kdf
    
    def verify_key(self, kdf, key, use_verify_key = True):
        if use_verify_key:
            return kdf.verify(self.input_key, key)


# KBKDF (Key Based Key Derivation Function) 
# is defined by the NIST SP 800-108 document, 
# to be used to derive additional keys from a key that has been 
# established through an automated key-establishment scheme.
#
# Warning
# 
# KBKDFCMAC should not be used for password storage.

class KBKDFCMAC:
    def __init__(self):
        self.salt_length = int('32')
        self.encoding_type = algorithms.AES
        self.key_material = bytes("32 bytes long input key material", encoding="utf8")
        self.label = bytes("KBKDF CMAC Label",encoding="utf8")
        self.context = bytes("KBKDF CMAC Context", enconding="utf8")
        self.length_of_binary_representation = int('4')
        self.binary_representation_length = int('4')
    
    def generate_kbkdfcmac(self, use_kbkdfcmac = True):
        if use_kbkdfcmac:
            kdf = KBKDFCMAC(algorithm=self.encoding_type,mode=Mode.CounterMode,length=self.salt_length,rlen=self.length_of_binary_representation,llen=self.binary_representation_length,location=CounterLocation.BeforeFixed,label=self.label,context=self.context,fixed=None)
        return kdf
    
    def derive_key(self, kdf, use_derive_key = True):
        if use_derive_key:
            key = kdf.derive(self.key_material)
        return key
    
    def second_kdkdfmac(self, use_second_kdkdfmac = True):
        if use_second_kdkdfmac:
            kdf = KBKDFCMAC(algorithm=self.encoding_type,mode=Mode.CounterMode,length=self.salt_length,rlen=self.length_of_binary_representation,llen=self.binary_representation_length,location=CounterLocation.BeforeFixed,label=self.label,context=self.context,fixed=None)
        return kdf
    
    def verify_key(self, kdf, key, use_verify_key = True):
        if use_verify_key:
            return kdf.verify(self.key_material, key)

# X963KDF (ANSI X9.63 Key Derivation Function) is defined by ANSI 
# in the ANSI X9.63:2001 document, 
# to be used to derive keys for use after a Key Exchange negotiation operation.
#
# SECG in SEC 1 v2.0 recommends that ConcatKDFHash 
# be used for new projects. 
# This KDF should only be used for backwards compatibility with pre-existing protocols. 
#
# Warning 
# X963KDF should not be used for password storage.

class X963KDF:
    def __init__(self):
        self.key_length = int('32')
        self.encoding_type = hashes.SHA256()
        self.input_key = bytes("input key", encoding = "utf8")
        self.sharedinfo = bytes("ANSI X9.63 Example", encoding="utf8")
    
    def generate_xkdf(self, use_xkdf = True):
        if use_xkdf:
            xkdf = X963KDF(algorithm=self.encoding_type,length=self.key_length,sharedinfo=self.sharedinfo)
        return xkdf
    
    def derive_key(self, xkdf, use_derive_key = True):
        if use_derive_key:
            key = xkdf.derive(self.input_key)
        return key
    
    def second_xkdf(self, use_second_xkdf = True):
        if use_second_xkdf:
            xkdf = X963KDF(algorithm=self.encoding_type,length=self.key_length,sharedinfo=self.sharedinfo)
        return xkdf
    
    def verify_key(self, key, use_verify_key = True):
        if use_verify_key:
            return xkdf.verify(self.input_key, key)
