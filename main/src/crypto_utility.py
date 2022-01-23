from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import load_pem_public_key


key_type        = rsa.RSAPublicKey
parameter_type  = dh.DHParameters

def check_data_type(message_type, data_type):
    return isinstance(message_type, data_type)

def check_pem_public_key_type(public_pem_data, key_type):
        key = load_pem_public_key(public_pem_data)
        if key:
            check_key_type = check_data_type(key, key_type)
        if check_key_type == True:
            return True

def check_pem_parameter_type(parameters_pem_data, parameter_type):
    parameters = load_pem_parameters(parameters_pem_data)
    if parameters:
        check_parameters_type = check_data_type(parameters, parameter_type)
    if check_parameters_type == True:
        return True
