import random
import hashlib
from hashlib import sha256
import time
# Generate a signature / verification key pair.
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify 
from aux_functions import savekey, readkey, pack, unpack 
#files
HASH_BILL = 'hash_bill.txt'
SIGNATURE = 'signature.txt'

#code
G = EcGroup()
sig_key = unpack(readkey('sig_key.txt'))
print(sig_key)

ver_key = unpack(readkey('ver_key.txt'))
time.sleep(3)

bill_number = str(random.randint(1, 10000))
bill_hashed = hashlib.sha256(bill_number.encode('utf-8')).digest()

#bill_number = sha1(b'12345').digest()
print bill_number
savekey(HASH_BILL, pack(bill_hashed))
time.sleep(3)
print unpack(readkey('hash_bill.txt'))
# Sign and verify signature
signature_bill = do_ecdsa_sign(G, sig_key, bill_hashed)
savekey(SIGNATURE, pack(signature_bill))
time.sleep(3)
sig = unpack(readkey('signature.txt'))
assert do_ecdsa_verify(G, ver_key, sig, bill_hashed)
