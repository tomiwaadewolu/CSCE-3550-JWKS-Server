#Name: Ireoluwatomiwa Adewolu
#CSCE 3550.001
#Generating RSA Pair Keys

import random
import math

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
    #Step 1: Selecting Two Prime Numbers (p and q)
    p = get_prime()
    q = get_prime()

    #Step 2: Calculating the Modulus (n = p * q)
    n = p * q

    #Step 3: Calculating Euler's Totient Function (g = (p-1) * (q-1))
    g = (p - 1) * (q -1)

    #Step 4: Choosing the Public Key Exponent (e)
    #e is a value between 1 and g that is coprime (gcd function) with g
    while True:
        e = random.randint(2, g)
        if math.gcd(e, g) == 1:
            break

    #Step 5: Calculating the Private Key Exponent (d = e ^ (-1))
    d = pow(e, -1, g)

    #Step 6: Public and Private Key Pair
    #RSA Public Key: n and e
    #RSA Private Key: n and d
    return ((n, e), (n, d))

#Source: https://pythonmania.org/python-program-for-rsa-algorithm/