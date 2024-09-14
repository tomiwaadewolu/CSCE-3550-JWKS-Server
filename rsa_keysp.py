#Name: Ireoluwatomiwa Adewolu
#CSCE 3550.001
#Generating RSA Pair Keys

import random
import math
import time
from uuid import uuid4
import base64
from flask import Flask, jsonify
import jwt
import threading

#function to check if a number is prime
def check_prime(n):
    if n<=1:
        return False
    #** operator is exponentiation operator
    for i in range(2, int(n ** 0.5) + 1): 
        if n % i == 0:
            return False
        return True
    
#function to get prime numbers
def get_prime():
    while True:
        #getting random integers between 2^8 and 2^16
        prime = random.randint(2 ** 8, 2 **16)
        if check_prime(prime):
            return prime

#function to get RSA Key Pairs
def get_key_pair():
    #step 1: Selecting Two Prime Numbers (p and q)
    p = get_prime()
    q = get_prime()

    #step 2: Calculating the Modulus (n = p * q)
    n = p * q

    #step 3: Calculating Euler's Totient Function (g = (p-1) * (q-1))
    g = (p - 1) * (q -1)

    #step 4: Choosing the Public Key Exponent (e)
    #e is a value between 1 and g that is coprime (gcd function) with g
    while True:
        e = random.randint(2, g)
        if math.gcd(e, g) == 1:
            break

    #step 5: Calculating the Private Key Exponent (d = e ^ (-1))
    d = pow(e, -1, g)

    #step 6: Public and Private Key Pair
    #RSA Public Key: n and e
    #RSA Private Key: n and d
    return ((n, e), (n, d))

#defining array of keys
keys = {}

#function to add new key with unique kid and expiration time
def add_key():
    p, q = get_key_pair()
    #creating id for new key
    kid = str(uuid4())
    #making key expire in 24 hours
    expire_time = time.time() + 86400

    #setting members of new key
    keys[kid] = {
        'private_key': p,
        'public_key': q,
        'expiry': expire_time
    }

#making app for flask
app = Flask(__name__)

@app.route('/jwks', methods=['GET'])

#function for jwks
def jwks():
    #making jwks keys
    jwks_keys = []

    #setting members of jwks key
    for kid, key_data in keys.items():
        jwks_keys.append({
            'kid': kid,
            'kty': 'RSA',
            'use': 'sig',
            'alg': 'RS256',
            'n': n, #CHECK
            'e': e #CHECK
        })

    #return jwks keys
    return jsonify({'keys': jwks_keys})

#making JWT issuance endpoint with expired key option
@app.route('/jwks', methods=['POST'])

#function to issue jwts using the "/token" endpoint
def issue_token():
    use_expired_key = request.args.get('useExpiredKey', 'false').lower() == 'true'

    #get current or expired key
    key_to_use = None
    
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
        'user_id': 'abc1234' #example id
        'exp': time.time() + 3600 #expires after 1 hour
    }

    #token endpoint
    token  = jwt.encode(payload, key_data['private_key'], algorithm='RS256', headers={'kid': kid})

    #return jwt token
    return jsonify({'token': token})

#function to remove expired keys and add new keys (rotating keys)
def rotate_keys():
    while True:
        #keys rotate hourly
        time.sleep(3600)
        curr_time = time.time()

        #remove expired keys
        expired_keys = [kid for kid, data in keys.items() if data['expiry'] < curr_time]
        for kid in expired_keys:
            del keys[kid]

        #add new keys
        add_key()

    #rotate keys in background
    threading.Thread(target=rotate_keys, daemon=True).start()

#JWT Verification

#Run Flask App

#Source: https://pythonmania.org/python-program-for-rsa-algorithm/
