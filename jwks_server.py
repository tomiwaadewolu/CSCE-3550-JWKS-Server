#Name: Ireoluwatomiwa Adewolu
#CSCE 3550.001
#Generating RSA Pair Keys
#Building JWKS Server

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
from uuid import uuid4
import base64
from flask import Flask, jsonify, request
import jwt
import threading

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

    #return private and public PEMs
    return private_pem, public_pem

keys = {} #defining array of keys
key_lock = threading.Lock() #lock for threads

#function to add new key with unique kid and expiration time
def add_key():
    with key_lock:
        private_pem, public_pem = get_key_pair() #getting RSA key pair
        kid = str(uuid4()) #creating id for new key
        expiry_time = time.time() + 86400 #making key expire in 24 hours

        #setting members of new key
        keys[kid] = {
            'private_key': private_pem,
            'public_key': public_pem,
            'expiry': expiry_time
        }

#creating key
add_key()

#making an instance (app) of Flask class
app = Flask(__name__)

#making URL path for the app route to use for HTTP GET requests to /jwks
@app.route('/jwks', methods=['GET'])

#function for getting jwks data in response to a HTTP GET request at the /jwks endpoint
def jwks():
    jwks_keys = []

    with key_lock:
        for kid, key_data in keys.items():
            #convert PEM public key to modulus and exponent for JWKS format
            public_key = serialization.load_pem_public_key(key_data['public_key'])
            public_numbers = public_key.public_numbers()

            #setting members of jwks key
            jwks_keys.append({
                'kid': kid, #key id
                'kty': 'RSA', #key type
                'use': 'sig', #use of key (for signing operations)
                'alg': 'RS256', #algorithm
                'n': base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).decode('utf-8').rstrip('='), #modulus
                'e': base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).decode('utf-8').rstrip('=') #exponent
            })

    #return jwks keys in JSON format
    return jsonify({'keys': jwks_keys})

#function for decoding private ket for jwt encoding
def load_private_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)

#making URL path for the app route to use for HTTP POST requests to /token
@app.route('/token', methods=['POST'])

#function for issueing jwts in response to a HTTP POST request at the /token endpoint
def issue_token():
    #bool for checking to use an expired key
    use_expired_key = request.args.get('useExpiredKey', 'false').lower() == 'true'

    #getting current or expired key
    key_to_use = None

    with key_lock:
        if use_expired_key:
            for kid, key_data in keys.items():
                #use oldest key if the key is expired
                if key_data['expiry'] < time.time():
                    key_to_use = (kid, key_data)
                    break

        #else, use most recent unexpired key
        else:
            for kid, key_data in keys.items():
                if key_data['expiry'] > time.time():
                    key_to_use = (kid, key_data)
                    break

    #if there is no key found, return error
    if key_to_use is None:
        return jsonify({'error': 'No valid key found'}), 500

    #set keys to use found key
    kid, key_data = key_to_use
    payload = {
        'user_id': '12345', #example id
        'exp': time.time() + 3600 #expires after 1 hour
    }

    #encoding jwt using private key
    private_key = load_private_key(key_data['private_key'])
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': kid})

    #return jwt in JSON format
    return jsonify({'token': token})

#function to remove expired keys and add new keys (rotating keys)
def rotate_keys():
    while True:
        #keys rotate hourly
        time.sleep(3600)

        with key_lock:
            current_time = time.time()

            #remove expired keys
            expired_keys = [kid for kid, data in keys.items() if data['expiry'] < current_time]
            for kid in expired_keys:
                del keys[kid]

            #add new keys
            add_key()

#rotate keys in background
threading.Thread(target=rotate_keys, daemon=True).start()

#function to decode public key for jwt verification
def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

#making URL path for the app route to use for HTTP POST requests to /verify
@app.route('/verify', methods=['POST'])

#function to verify jwts based on the kid in the jwt header
def verify_token():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'Token not provided'}), 400

    #decoding token header to get kid
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']

    #checking for kid's public key
    if kid not in keys:
        return jsonify({'error': 'Invalid key ID'}), 401

    #setting kid's public key
    public_key = load_public_key(keys[kid]['public_key'])

    #trying to decode and verify the jwt
    try:
        decoded = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({'valid': True, 'payload': decoded})
    
    #handling error case for expired token
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    
    #handling other invalid token error cases
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    #handling error case for a valid token that is not found
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#funtion to extract jwt from header with request object as parameter
def extract_jwt_from_header(request):
    #checking if the header exists
    auth_header = request.headers.get('Authorization')
    
    #if the header has a value, extract the token, else return None
    if auth_header:
        #remove spaces from header
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header
        return token
    return None

#making URL path for the app route to use for HTTP POST requests to /verify_with_header
@app.route('/verify_with_header', methods=['POST'])

#function to verify jwts that need to be extraxted from header 
def verify_token_with_header():
    #extracting the jwt
    token = extract_jwt_from_header(request)

    #returning error if token is not found in header
    if not token:
        return jsonify({'error': 'Token not provided in Authorization header'}), 400
    
    #calling the verify_token function
    return verify_token()

#making URL path for the app route to use for HTTP POST requests to /auth
@app.route('/auth', methods=['POST'])

#function for authenticating
def auth():
    #returning jwt
    return jsonify({'message': 'Authentication endpoint'}), 200

#making URL path for the app route to use for HTTP POST requests to /.well-known/jwks.json
@app.route('/.well-known/jwks.json', methods=['GET'])

#function for redirecting jwks
def jwks_redirect():
    return jwks()

#function for handling unsupported methods
@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

#running the server on flask at port 8080
if __name__ == "__main__":
    app.run(debug=True, port=8080)

#Source: https://chatgpt.com/c/66df21d9-b94c-800e-9eba-6f2130cde693
