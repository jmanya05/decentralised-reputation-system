##########################################
# Client asking for credentials
#
# version: 1.0.2
##########################################
# coconut
from coconut.scheme import *
# aux functions
from aux_functions import pack, unpack, savekey, readkey
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
ROUTE_SIGN_PRIVATE = "/sign/cred"
ROUTE_KEY_SET = "/key/set"

#Files to be saved during credential issuance
VVK = "vvk.txt"
CREDENTIAL = 'credential.txt'
PRIVATE_SIGN_DB = 'private_sign.json'
GAMMA = 'gamma.txt'
PARAMETER_D = 'd.txt'

# Servers running in internet
SERVER_ADDR = [
"ec2-18-211-2-124.compute-1.amazonaws.com",
"ec2-3-218-186-101.compute-1.amazonaws.com",
"ec2-3-221-244-24.compute-1.amazonaws.com",
"ec2-3-224-131-122.compute-1.amazonaws.com",
"ec2-3-224-174-146.compute-1.amazonaws.com"]

SERVER_PORT = [80] * len(SERVER_ADDR)

# crypto
params = setup()
(d, gamma) = elgamal_keygen(params)
savekey(PARAMETER_D, pack(d))
savekey(GAMMA, pack(gamma))

# parameters
private_m = [d] # private attributes
public_m = [40]  # public attributes
N = len(SERVER_ADDR)
t  = 3
(sk, vk) = ttp_keygen(params, t, N)
#print(sk)
vk1 = list(vk[:3]) + [None] + list(vk[4:5])
aggr_vk = agg_key(params, vk1)
savekey(VVK, pack(aggr_vk))

# timings
mem = []
tic = 0

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
        #print(loads(r.text)["message"])

###############################################
# utils for client to authorities communication
###############################################
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
        #print(r.text)
        assert loads(r.text)["status"] == "OK"
        record(r.elapsed.total_seconds(), loads(r.text))


# response handler
def response_handler(response, *args, **kwargs):
    toc = get_time()

# store data in mem
def record(time, data):
    mem.append({'time':time, 'request':data})

# store mem to file
def save(filename):
	with open(filename, 'w') as file:
		file.write('[')
		for i in range(len(mem)):
			mem[i]['time'] = mem[i]['time'] * 1000 
			file.write(dumps(mem[i]))
			if i != len(mem)-1: file.write(',')
		file.write(']')

##########################################
# request blind signature
##########################################
def request_blind_sign():
    (cm, c, proof_s) = prepare_blind_sign(params, gamma, private_m)
    json = {
        "cm": pack(cm),
        "c": pack(c),
        "proof_s": pack(proof_s),
        "gamma": pack(gamma)
#        "public_m": pack(public_m)
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
     sig1 = (h, elgamal_dec(params, d, enc_sig1))

    # unblind sig2 from server2
     blind_sig2 = unpack(blind_sign[1]["request"]["load"])
     (h, enc_sig2) = blind_sig2
     sig2 = (h, elgamal_dec(params, d, enc_sig2))

    # unblind sig3 from server3
     blind_sig3 = unpack(blind_sign[2]["request"]["load"])
     (h, enc_sig3) = blind_sig3
     sig3 = (h, elgamal_dec(params, d, enc_sig3))

    # unblind sig4 from server4
     blind_sig4 = unpack(blind_sign[3]["request"]["load"])
     (h, enc_sig4) = blind_sig4
     sig4 = (h, elgamal_dec(params, d, enc_sig4))

    # unblind sig5 from server5
     blind_sig5 = unpack(blind_sign[4]["request"]["load"])
     (h, enc_sig5) = blind_sig5
     sig5 = (h, elgamal_dec(params, d, enc_sig5))

    #aggregate signs
     sigs = [sig1, sig2, sig3, sig4, sig5]
     sigs_list = [None] + sigs[1:3] + [None] + [sigs[4]]
     sigma = agg_cred(params, sigs_list)
     #aggr_vk = unpack(readkey('vvk.txt'))
     #Theta = prove_cred(params, aggr_vk, sigma, private_m)
     #assert verify_cred(params, aggr_vk, Theta, public_m = public_m)
     savekey(CREDENTIAL, pack(sigma))
     #print (pack(sigma))
     return sigma

##########################################
# Signature showing and verification
##########################################
def show_and_verify():

    aggr_vk = unpack(readkey('vvk.txt'))
    params_ver = setup()
    sigma = get_sign_final()
    Theta = prove_cred(params_ver, aggr_vk, sigma, private_m)

    assert verify_cred(params_ver, aggr_vk, Theta)

##########################################
# main function
##########################################
def main():
    # test server connection
    test_connection()
    print('[OK] Test connection.')

    # Key distribution
    set_key()
    print('[OK] Key distribution.')
    time.sleep(5)

    # request blind sign to authorities
    print('[OK] Requesting blind sign of private and public attributes...')
    time.sleep(5)
    # attribute private key to each authority

    del mem[:]
    request_blind_sign()
    time.sleep(5)
    save(PRIVATE_SIGN_DB)
    print('[OK] Done.')

    # Build credential
    #time.sleep(5)
    print('[OK] Building credential...')
    get_sign_final()
    time.sleep(3)
    print('[OK] Done.')

    # Show and verify credential
    #time.sleep(5)
    print('[OK] Verifying credential...')
    time.sleep(5)
    show_and_verify()
    print('[OK] Credential verified!')

##########################################
# program entry point
##########################################
if __name__ == "__main__":
    main()
##########################################
