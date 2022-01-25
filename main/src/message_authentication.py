from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

# While cryptography supports multiple MAC algorithms, 
# we strongly recommend that HMAC should be used unless you have a very specific need.
#
# For more information on why HMAC is preferred, see Use cases for CMAC vs. HMAC?

class Cipher_based_message_authentication_code:
