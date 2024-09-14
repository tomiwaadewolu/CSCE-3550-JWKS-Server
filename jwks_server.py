#Name: Ireoluwatomiwa Adewolu
#CSCE 3550.001
#Generating RSA Pair Keys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#function to get RSA key pairs
def get_key_pair():
    #getting private key
    private_key = rsa.generate_private_key(
        public_exponent = 65537, #e = Fermat prime number
        key_size = 2048 #n = modulus
    )

    #PEM encoded version of private key
    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM, #key is encoded using PEM
        format = serialization.PrivateFormat.PKCS8, #key is formatted using PKCS#8
        encryption_algorithm = serialization.NoEncryption() #key is not encrypted
    )

    #PEM encoded version of public key
    public_pem = private_key.public_key().public_bytes(
        encoding = serialization.Encoding.PEM, #key is encoded using PEM
        format = serialization.PublicFormat.SubjectPublicKeyInfo #key is formatted using SubjectPublicKeyInfo
    )

#Source: https://chatgpt.com/c/66df21d9-b94c-800e-9eba-6f2130cde693