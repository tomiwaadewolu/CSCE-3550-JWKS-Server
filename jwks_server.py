#Name: Ireoluwatomiwa Adewolu
#euid: ija0023
#CSCE 3550.001
#Generating RSA Pair Keys
#Building JWKS Server

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import jwt
import datetime
import uuid

#making an instance (app) of Flask class
app = Flask(__name__)

#getting private key
private_key = rsa.generate_private_key(
    public_exponent=65537, #e = Fermat prime number
    key_size=2048 #n = modulus
)

#getting expired key
expired_key = rsa.generate_private_key(
    public_exponent=65537, #e = Fermat prime number
    key_size=2048 #n = modulus
)

#PEM encoded version of private key
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM, #key is encoded using PEM
    format=serialization.PrivateFormat.TraditionalOpenSSL, #key is formatted using TraditionalOpenSSL
    encryption_algorithm=serialization.NoEncryption() #key is not encrypted
)

#PEM encoded version of expired key
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM, #key is encoded using PEM
    format=serialization.PrivateFormat.TraditionalOpenSSL, #key is formatted using TraditionalOpenSSL
    encryption_algorithm=serialization.NoEncryption() #key is not encrypted
)

#convert RSA numbers to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x') #converting value to lowercase hex

    #making the string an even length for better conversion from hex to byted
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex

    value_bytes = bytes.fromhex(value_hex) #converting hex to bytes
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=') #encoding the bytes in Base64
    return encoded.decode('utf-8') #returning the string in decoded UTF-8

#get n and e from public key
def get_jwks_key_data(public_key):
    #getting the public numbers
    public_numbers = public_key.public_numbers()

    #returning n and e
    return {
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }

#making URL path for the app route to use for HTTP GET requests to /jwks
@app.route('/.well-known/jwks.json', methods=['GET'])

#function for getting jwks data in response to a HTTP GET request at the /jwks endpoint
def jwks():
    #setting members of jwks key
    jwks_keys = [{
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": "goodKID",
            "n": get_jwks_key_data(private_key.public_key())['n'],
            "e": get_jwks_key_data(private_key.public_key())['e']
        }]
    
    #return jwks keys in JSON format
    return jsonify({"keys": jwks_keys})

#making URL path for the app route to use for HTTP POST requests to /auth
@app.route('/auth', methods=['POST'])

#function for issueing jwts in response to a HTTP POST request at the /auth endpoint
def auth():
    #getting the expired parameter
    expired = request.args.get('expired')

    #putting kids in a headers dictionary
    headers = {
        "kid": "goodKID"
    }
    
    if expired:
        headers["kid"] = "expiredKID" #set the kid as expired
        exp_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)  #make jwt expired (time is -1 hour)
        
        #setting members of jwt
        encoded_jwt = jwt.encode(
            {"user": "username", "exp": exp_time},
            expired_pem,
            algorithm="RS256",
            headers=headers
        )
    
    else:
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  #make the jwt expire in 1 hour
        
        #setting members of jwt
        encoded_jwt = jwt.encode(
            {"user": "username", "exp": exp_time},
            pem,
            algorithm="RS256",
            headers=headers
        )
    
    #return jwt in JSON format
    return jsonify({"token": encoded_jwt})

#making path for 405 errors
@app.errorhandler(405)

#function for handling unsupported methods
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

#running the server on flask at port 8080
if __name__ == "__main__":
    app.run(port=8080)

#ChatGPT was used to ask for steps to starting the server, running the server,
#explaining unclear parts of the code, and help with debugging

#Examples of prompts used:
# -Please explain steps to building a RESTful JWKS server
# -Please explain steps to running a JWKS server
# -Please explain the given portion of code
# -Please identify issues in the given code
