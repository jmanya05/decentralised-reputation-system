##########################################
# Third trusted party issuing keys
#
# version: 0.0.1
##########################################
# coconut
# coconut
from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from lib import ttp_th_keygen, aggregate_th_sign
from aux_functions import savekey, readkey, pack, unpack
# petlib import-export
#from utils import pack, unpack
# standard REST lib
from json  import loads, dumps
import requests
# async REST lib
import asyncio
import concurrent.futures
#import grequests
# timing & db
import time
#from tinydb import TinyDB, Query

##########################################
# static fields
SERVER_ADDR = [
"ec2-18-211-2-124.compute-1.amazonaws.com",
"ec2-3-221-244-24.compute-1.amazonaws.com",
"ec2-3-218-186-101.compute-1.amazonaws.com",
"ec2-3-224-131-122.compute-1.amazonaws.com",
"ec2-3-224-174-146.compute-1.amazonaws.com"
]

SERVER_PORT = [80] * len(SERVER_ADDR)

ROUTE_SERVER_INFO = "/"
ROUTE_KEY_SET = "/key/set"
VVK = "vvk.txt"

# parameters
N = len(SERVER_ADDR)
T = 4 # does not impact latency

# crypto
params = setup()
(sk, vk, vvk) = ttp_th_keygen(params, T, N)
savekey(VVK, pack(vvk))

# timings
mem = []
tic = 0

##########################################
# utils
##########################################
# test server connection
##########################################
def test_connection():
    for i in range(N):
        r = requests.get(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_SERVER_INFO
        )
        assert loads(r.text)["status"] == "OK"

##########################################
# set keys
##########################################
def set_key():
    for i in range(N):
        r = requests.post(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_KEY_SET,
            data = dumps({"sk": pack(sk[i]),"vk": pack(vk[i])})
        )
        assert loads(r.text)["status"] == "OK"
        print(loads(r.text)["message"])
        print('\n')

##########################################
# main function
##########################################
def main():
    # test server connection
    test_connection()
    print('[OK] Test connection.')

    # attribute private key to each authority
    set_key()
    print('[OK] Key distribution.')

##########################################
# program entry point
##########################################
if __name__ == "__main__":
    main()
##########################################
