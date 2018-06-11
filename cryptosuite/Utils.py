import random
import datetime
from functools import reduce

# ==============================================
# Utility functions for cryptographic algorithms
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

# set RNG seed with respect to current time
# Note that linear congruential PRNG's are NOT cryptographically secure!
random.seed((datetime.datetime.now() 
    - datetime.datetime.utcfromtimestamp(0)).total_seconds())

# MARK: primality testing & other related functions

def miller_rabin(n, confidence = 40):
    if n == 3:
        return True
    elif n < 3 or n % 2 == 0:
        return False
    
    composite = False

    # Obtain s, d from (n-1) = 2^(s) * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1

    # witness loop
    for _ in range(confidence):
        r = random.randint(2, n - 2)
        x = pow(r, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            elif x == n - 1:
                composite = False
                break
        if composite:
            return False
        composite = False
    return True

def randomNumber(bitLength):
    return random.randint((1 << bitLength - 1) + 1, (1 << bitLength))

def randomLargePrime(bitLength):
    a = 2
    while not miller_rabin(a):
        a = randomNumber(bitLength)
    return a

def EEA(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = EEA(b % a, a)
        return (g, y - (b // a) * x, x)

def multiplicative_inverse(a, n):
    gcd, x, _ = EEA(a, n)
    if gcd == 1:
        return x % n
    else:
        raise ValueError("inverse of " + str(a) + " does not exist!")

def crt(moduli, remainders):
    # <moduli> and <remainders> are iterables
    mod_product = reduce((lambda x, y: x*y), moduli)
    
    total = 0
    for modulus, remainder in zip(moduli, remainders):
        y_i = mod_product // modulus
        z_i = multiplicative_inverse(y_i, modulus)
        total += remainder * y_i * z_i % mod_product
    return total % mod_product

# MARK: number theoretic tools

def getGroupWithGenerator(bitLength):
    # returns a prime p along with a
    # generator g of Z_p
    p = 2
    while not miller_rabin(p):
        q = randomLargePrime(bitLength)
        p = (2 * q) + 1
    
    # 2 - find a generator
    g = random.randint(2, q)
    while not (pow(g, q, p) and g ** 2 != 1):
        g = random.randint(2, q)
    
    return (p, g)