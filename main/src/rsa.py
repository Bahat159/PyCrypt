from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# RSA is a public-key algorithm for encrypting and signing messages.
#
# Unlike symmetric cryptography, where the key is typically just a random series of bytes, 
# RSA keys have a complex internal structure with specific mathematical properties.

# Generates a new RSA private key. key_size describes how many bits long the key should be. 
# Larger keys provide more security; 
# currently 1024 and below are considered breakable while 2048 or 4096 are reasonable default key sizes for new keys. 
#
# The public_exponent indicates what one mathematical property of the key generation will be.
# Unless you have a specific reason to do otherwise, you should always use 65537.

class RSA_Key_Algorithm:
    def __init__(self):
        self.rsa_cipher                 = True
        self.hash_type                  = hashes.SHA256()
        self.salt_key_length            = padding.PSS.MAX_LENGTH
        self.key_size                   = int('2048')  # (key size can be of anylength, 1024, 2048, 4096 and so on)
        self.public_exponent            = int('65537')
        self.message_to_sign            = bytes('Your message to sign')
        self.message_to_sign_and_verify = bytes('Your message to sign and verify')
        self.key_serialize_password     = bytes('your password')
        self.serialization_encoding     = serialization.Encoding.PEM
        self.key_serialization_format   = serialization.PrivateFormat.PKCS8
        self.serialze_with_no_pass_encryption_algorithm  = serialization.NoEncryption()
        self.key_serialization_format_no_password        = serialization.PrivateFormat.TraditionalOpenSSL
        self.serialze_with_password_encryption_algorithm = serialization.BestAvailableEncryption(self.key_serialize_password)
    
    def generate_rsa_private_key(self, generate_new_key = True):
        if generate_new_key:
            private_key = rsa.generate_private_key(public_exponent=self.public_exponent,key_size=self.key_size,)
        return private_key
    
    # Key Loading
    
    # If you already have an on-disk key in the PEM format 
    # (which are recognizable by the distinctive -----BEGIN {format}----- and -----END {format}----- markers), 
    # you can load it:

    def load_private_key_from_disk_PEM_FORMAT(self, file_path_to_key_dot_pem, file_passsword = None):
        with open(file_path_to_key_dot_pem, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(),password=file_passsword,)
        return private_key
    
    # Key serializatio
    # If you have a private key that you’ve loaded you can use private_bytes() to serialize the key.

    def key_serialization_with_password(self, password_inuse = True):
        if password_inuse:
            pem = private_key.private_bytes(encoding=self.serialization_encoding,format=self.key_serialization_format,encryption_algorithm=self.serialze_with_password_encryption_algorithm)
        return pem.splitlines()[0]
    

    def key_serialization_with_no_password(self, password_inuse = False):
        if password_inuse == False:
            pem = private_key.private_bytes(encoding=self.serialization_encoding,format=self.key_serialization_format_no_password,encryption_algorithm=self.serialze_with_no_pass_encryption_algorithm)
        return pem.splitlines()[0]
    
    # Message signing
    # This allows anyone with the public key to verify that the message 
    # was created by someone who possesses the corresponding private key.
    # RSA signatures require a specific hash function, and padding to be used.

    def message_signature(self, sign_message = True):
        if sign_message:
            signature = private_key.sign(self.message_to_sign,padding.PSS(mgf=padding.MGF1(self.hash_type),salt_length=self.salt_key_length),self.hash_type)
        return signature

    # Key verification 
    # If you have a public key, a message, a signature, 
    # and the signing algorithm that was used you can check that the private key 
    # associated with a given public key was used to sign that specific message

    def serialized_key_verification(self, private_key, signature, message, verify_key = True):
        if private_key:
            public_key = private_key.public_key()
            public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(self.hash_type),salt_length=self.salt_key_length),self.hash_type)
            return public_key
    
    def serialize_large_key_verification(self, signature, verify_key = True):
        if verify_key:
            chosen_hash = self.hash_type
            hasher = hashes.Hash(chosen_hash)
            hasher.update(self.message_to_sign_and_verify)
            hasher.update(self.message_to_sign_and_verify)
            digest = hasher.finalize()
            public_key.verify(signature, digest, padding.PSS(mgf=padding.MGF1(self.hash_type),salt_length=self.salt_key_length),utils.Prehashed(chosen_hash))
            return public_key
    
    # encryption is performed using the public key, meaning anyone can encrypt data. 
    # The data is then decrypted using the private key.

    def encrypt_message_data(self, public_key, message_to_encrypt, encrypt_data = True):
        if encrypt_data:
            message = bytes(message_to_encrypt)
            ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_type),algorithm=self.hash_type,label=None))
        return ciphertext
    

    # Once you have an encrypted message, it can be decrypted using the private key.

    def decrypt_message_data(self, private_key, ciphertext, decrypt_message = True):
        if decrypt_message:
            plaintext = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_type),algorithm=self.hash_type,label=None))
        return plaintext

    def decryption_verification(self, plaintext, message, decrypt_verification = True):
        if decrypt_verification:
            if plaintext == message:
                return True
