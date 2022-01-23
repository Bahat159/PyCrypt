from crypto_utility import check_data_type  
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key



class Key_Serialization:
    def __init__(self):
        self.password = None
        self.rsa_serialization_type = rsa.RSAPrivateKey
        self.dsa_serialization_type = dsa.DSAPrivateKey

    def load_and_sign_pem_private_key(self, pem_data, message):
        key = load_pem_private_key(pem_data, password=self.password)
        rsa_serialize_type_check = check_data_type(key, self.rsa_serialization_type)
        dsa_serialize_type_check = check_data_type(key, self.dsa_serialization_type)
        if rsa_serialize_type_check:
            signature = sign_with_rsa_key(key, message)
        elif serialize_type_check:
            signature = sign_with_dsa_key(key, message)
        else:
            raise TypeError
        return signature
