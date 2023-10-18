import json

from gmpy2 import powmod, invert


# Please check README.md for the details of the task. For modular arithmetic, I have used gmpy2, which is a Python
# extension module that supports multiple-precision arithmetic. In particular, I have used the following functions of
# gmpy2 for fast modular exponentiation and inverse:
# 1. powmod(x, y, m): returns (x ** y) mod m
# 2. invert(x, m): returns y such that x * y == 1 modulo m
# More details about the library present here: https://gmpy2.readthedocs.io/
# To install gmpy2, simply run from terminal: pip install 'gmpy2==2.0.8'
def get_nonce(p, q, g):
    for k in range(1, 2 ** 16):
        if r == powmod(g, k, p) % q:
            return k


input_file = open('input.json')
my_input = json.load(input_file)

p = my_input['p']
q = my_input['q']
g = my_input['g']
m = my_input['m']
h = my_input['h']
y = my_input['y']
r = my_input['r']
s = my_input['s']

k = get_nonce(p, q, g)
print(k)

x = (invert(r, q) * (k * s - int(h, 16))) % q
print(x)


# for testing purpose, based on verification algorithm for DSA
def verify(M, r, s, p, q, g, y):
    from hashlib import sha1
    m = int(sha1(M).hexdigest(), 16)
    w = invert(s, q)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    if v == r:
        return True
    return False


print(verify(m.encode('utf-8'), r, s, p, q, g, y))
