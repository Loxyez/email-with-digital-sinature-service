from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys

# set bits
bits = 60
msg = "Hello World"

# generate keys
if (len(sys.argv)>1):
    msg = str(sys.argv[1])
if (len(sys.argv)>2):
    bits = int(sys.argv[2])
    
p = Crypto.Util.number.getPrime(bits, Crypto.Random.get_random_bytes)
q = Crypto.Util.number.getPrime(bits, Crypto.Random.get_random_bytes)

n = p * q
PHI = (p-1) * (q-1)

v = 65537
s = (libnum.invmod(v, PHI))

D = bytes_to_long(msg.encode('utf-8'))

S = pow(D, s, n)
res = pow(S, v, n)

print(f'Message: {msg}\np={p}\nq={q}\n\nn={n}\nv={v}\ns={s}\n\nD={D}\nS={S}\nres={long_to_bytes(res)}')
