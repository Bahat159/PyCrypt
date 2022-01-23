from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import load_der_parameters

key_type               = rsa.RSAPublicKey
parameter_type         = dh.DHParameters
der_parameters_type    = dh.DHParameters
der_public_key_type    = rsa.RSAPublicKey
der_private_key_type   = rsa.RSAPrivateKey

def check_data_type(message_type, data_type):
    return isinstance(message_type, data_type)

# PEM is an encapsulation format, meaning keys in it can actually be any of several different key types. 
# However these are all self-identifying, so you don’t need to worry about this detail. 
# PEM keys are recognizable because they all begin with -----BEGIN {format}----- 
# and end with -----END {format}-----.

def check_pem_public_key_type(public_pem_data, key_type):
        key = load_pem_public_key(public_pem_data)
        if key:
            check_pem_key_type = check_data_type(key, key_type)
        if check_pem_key_type == True:
            return True

def check_pem_parameter_type(parameters_pem_data, parameter_type):
    parameters = load_pem_parameters(parameters_pem_data)
    if parameters:
        check_parameters_type = check_data_type(parameters, parameter_type)
    if check_parameters_type == True:
        return True

# DER is an ASN.1 encoding type. 
# There are no encapsulation boundaries and the data is binary. 
# DER keys may be in a variety of formats, 
# but as long as you know whether it is a public or private key the loading functions will handle the rest.

def check_der_private_key_type(der_data, der_private_key_type, password_type = None):
    if der_data:
        key = load_der_private_key(der_data, password=password_type)
    if key:
        check_der_private_key_type = check_data_type(key, der_private_key_type)
    if check_der_private_key_type:
        return True

def check_der_public_key_type(public_der_data, der_public_key_type):
    if public_der_data:
        key = load_der_public_key(public_der_data)
    if key:
        check_der_public_key_type = check_data_type(key, der_public_key_type)
    return True

def check_der_parameter_type(parameters_der_data):
    parameters = load_der_parameters(parameters_der_data)
    if parameters:
        check_der_paramters_type = check_data_type(parameters, der_parameters_type)
