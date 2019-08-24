#########################################

# Credential verification

#########################################

import time

#coconut
from coconut.scheme import *

# Auxiliary functions
from aux_functions import pack, unpack, savekey, readkey

#private_m = [20] * 2 # private client's attributes
#public_m = [40] * 1 # public client's attributes
private_m = [unpack(readkey('d.txt'))]
q = 7

#Function that performs show and verify Coconut's algorithms
def show_and_verify():
    aggr_vk = unpack(readkey('vvk.txt'))
    params_ver = setup(q)
    sigma = unpack(readkey('credential.txt'))
    Theta = prove_cred(params_ver, aggr_vk, sigma, private_m)

    assert verify_cred(params_ver, aggr_vk, Theta, public_m = [])

##########################################
# main function
##########################################

def main():

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
