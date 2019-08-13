##########################################
# Client asking for credentials
#
# version: 1.0.2
##########################################
# coconut
from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from lib import ttp_th_keygen, aggregate_th_sign
from aux_functions import readkey, pack, unpack
# petlib import-export
#from utils import pack, unpack
# standard REST lib
import json
from json  import loads, dumps
import requests
# async REST lib
import asyncio
import concurrent.futures
import requests
import grequests
# timing & db
import time
#from tinydb import TinyDB, Query

#Routes to servers
ROUTE_SERVER_INFO = "/"
ROUTE_SIGN_PRIVATE = "/sign/private"

# Servers running in internet
SERVER_ADDR = [
"ec2-18-211-2-124.compute-1.amazonaws.com",
"ec2-3-218-186-101.compute-1.amazonaws.com",
"ec2-3-221-244-24.compute-1.amazonaws.com",
"ec2-3-224-131-122.compute-1.amazonaws.com",
"ec2-3-224-174-146.compute-1.amazonaws.com"]

SERVER_PORT = [80] * len(SERVER_ADDR)

# parameters
ATTRIBUTE = 10
N = len(SERVER_ADDR)

# crypto
params = setup()

# timings
mem = []
tic = 0

PUBLIC_SIGN_DB = 'public_sign.json'
PRIVATE_SIGN_DB = 'private_sign.json'

##########################################
# utils
##########################################
# test server connection
def test_connection():
    for i in range(N):
        r = requests.get(
        "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_SERVER_INFO
        )
        assert loads(r.text)["status"] == "OK"

def get_time():
        return time.clock()

# make aync post requests
def async_request(route, json):
    unsent_request = [
        grequests.post(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+route,
            hooks={'response': response_handler},
            data=dumps(json)
        )
        for i in range(N)
    ]
    global tic
    tic = get_time()
    responses = grequests.map(unsent_request, size=N)
    #print(responses)
    for r in responses:
        #print(r.elapsed and r.elapsed.total_seconds() or "failed")
        assert loads(r.text)["status"] == "OK"
        record(r.elapsed.total_seconds(), loads(r.text))


# response handler
def response_handler(response, *args, **kwargs):
    toc = get_time()
    #record(toc-tic, loads(response.text))

# store data in mem
def record(time, data):
    mem.append({'time':time, 'request':data})

# stave mem to file
def save(filename):
        with open(filename, 'w') as file:
                file.write('[')
                for i in range(len(mem)):
                        mem[i]['time'] = mem[i]['time'] * 1000 # change to ms
                        file.write(dumps(mem[i]))
                        if i != len(mem)-1: file.write(',')
                file.write(']')

##########################################
# request blind signature
##########################################
def request_blind_sign():
    global priv
    global pub
    (priv, pub) = elgamal_keygen(params)
    (cm, c, proof_s) = prepare_blind_sign(params, ATTRIBUTE, pub)
    json = {
        "cm": pack(cm),
        "c": pack(c),
        "proof_s": pack(proof_s),
        "pub": pack(pub)
    }
    async_request(ROUTE_SIGN_PRIVATE, json)

##########################################
# Signature unblind and aggregation
##########################################

def get_sign_final():

    #read json from server
     blind_sign = json.loads(readkey('private_sign.json'))

    # unblind sig1 from server1
     blind_sig1 = unpack(blind_sign[0]["request"]["load"])
     (h, enc_sig1) = blind_sig1
     sig1 = (h, elgamal_dec(params, priv, enc_sig1))

    # unblind sig2 from server2
     blind_sig2 = unpack(blind_sign[1]["request"]["load"])
     (h, enc_sig2) = blind_sig2
     sig2 = (h, elgamal_dec(params, priv, enc_sig2))

    # unblind sig3 from server3
     blind_sig3 = unpack(blind_sign[2]["request"]["load"])
     (h, enc_sig3) = blind_sig3
     sig3 = (h, elgamal_dec(params, priv, enc_sig3))

    # unblind sig4 from server4
     blind_sig4 = unpack(blind_sign[3]["request"]["load"])
     (h, enc_sig4) = blind_sig4
     sig4 = (h, elgamal_dec(params, priv, enc_sig4))

    # unblind sig5 from server5
     blind_sig5 = unpack(blind_sign[4]["request"]["load"])
     (h, enc_sig5) = blind_sig5
     sig5 = (h, elgamal_dec(params, priv, enc_sig5))

    #aggregate signs
     sig_agg = aggregate_th_sign(params, [sig1, sig2, sig3, sig4, sig5])

    #signature randomization
     sig = randomize(params, sig_agg)
     return sig

##########################################
# Signature showing and verification
##########################################
def show_and_verify():
     vvk = readkey('vvk.txt')
     params1 = setup()
     sig = get_sign_final()
     (kappa, proof_v) = show_blind_sign(params1, unpack(vvk), ATTRIBUTE)

     assert blind_verify(params1, unpack(vvk), kappa, sig, proof_v)

##########################################
# main function
##########################################
def main():
    # test server connection
    test_connection()
    print('[OK] Test connection.')
    # request blind sign to authorities
    print('[OK] Requesting blind sign of credentials')
    del mem[:]
    request_blind_sign()
    time.sleep(5)
    save(PRIVATE_SIGN_DB)
    print('[OK] Done.')

    # Build credential
    time.sleep(5)
    print('[OK] Building credential...')
    get_sign_final()
    print('[OK] Done.')

    # Show and verify credential
    time.sleep(5)
    print('[OK] Verifying credential...')
    show_and_verify()
    print('[OK] Done.')

##########################################
# program entry point
##########################################
if __name__ == "__main__":
    main()
##########################################
