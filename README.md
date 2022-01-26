![GitHub Light](./base-octocat.svg)
# PyCrypt
- **Python Cryptography Library**
  -  A wrapper for the cryptography python library for efficiency and reliablity. An end to end encryption library to send encrypted messages across the internet, also among peer-  to-peer. This library should be revisited in order to make it robust and usable accross all platform.

- **Basic usage**
  - To import a whole wrapper library class module 
     `import Assymetric_Ed25519_signing`
  - To import a single library function. Example below imports generate_private _key to generate a new private key of Assymetric model
       `from Assymetric_Ed25519_signing import generate_ed25519_private_key`
- **Example Usage**
  - `class_object = symmertic_Encryption()`
  - `cipher_text, encryptor_tag = class_object.do_gcm_encrypt()` 
  - `print(cipher_text)`
  - `
b'\xe6d\xa6\xe3\xb1\x99,\xaa\xae\x91\x132"\x82Z\xd9\xb6}\x0f\x88\xdb\xb6\\\xd8}\xd5\xa0\x8dZ\x0b$\xb6\xb8\xb4\xb8T\xbb\x90\xdd\x06\x95\xdap\x96\xbeo\xaf\xe5\xf0\xcf\x865v\x0c\xd8\x0f\xe5\xd1tDu\xa8\x96\xeb&\n\xda\x1eY\xea\x99\xd0\x87\xfaf\x16\x9e\x04\xdc|$\xac/\x0cZ\xe1\xf9\xa8Hs\xb1\xed-\x1c\xe4\xc2\x1c8\n@\xaeH\xf2\xf2\xf9L\x83\xc5\xc9\xdc\xf8zb\xa1ay\xe8\xbbu\xa2\xd6\x16\x80\xc4Tx7\x12(\x02\xfa\x86\xb5\x8c\xacd\xf7J%\xaa\xabb\xc3z1\xd0'
`
  - `print(encryptor_tag)`
  - `b'\xfa\x04\xe4\xdavW\xe0\xd3\xa1\xce\x9a\x08\x8e\x8a\xf0\x03'`
  - `print(class_object.do_gcm_decrypt(cipher_text, encryptor_tag)))`
  - `b'a secret message! from the author. What if it is a file? \ `
  -  `Author: Busari Habibullah. \`
  - `Test Date: January 26, 2022. \`
  - `Company name: Sandcroft software.'`
