""" test for a voting system"""

####################################################################
# imports
###################################################################
# general
from hashlib import sha256, sha1
from multiprocessing import Process
from json import dumps, loads
import time
import unittest
import requests
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.reputation import contract as reputation_contract
from chainspacecontract.examples import reputation
from chainspacecontract.examples.utils import setup as pet_setup
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.utils import *
from coconut.utils import *
from coconut.scheme import *

from aux_functions import pack, unpack, savekey, readkey


####################################################################
## reputation voting parameters
UUID = Bn(1234) # reputation voting unique id (needed for crypto)

options = ['YES', 'NO']
# reputation voting owner parameters
pet_params = pet_setup()
(G, g, hs, o) = pet_params
t_owners, n_owners = 2, 3
v = [o.random() for _ in range(0,t_owners)]
sk_owners = [poly_eval(v,i) % o for i in range(1,n_owners+1)]
pk_owner = [xi*g for xi in sk_owners]
#l = [lagrange_basis(t_owners, o, i, 0) for i in range(1,t_owners+1)]
l = lagrange_basis(range(1,t_owners+1), o, 0)
aggr_pk_owner = ec_sum([l[i]*pk_owner[i] for i in range(t_owners)])

bp_params = setup() # bp system's parameters

# credential and merchant verification material
d = unpack(readkey('d.txt'))
aggr_vk = unpack(readkey('vvk.txt'))
sigma = unpack(readkey('credential.txt'))
merchant_vk = unpack(readkey('ver_key.txt'))

class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        with reputation_contract.test_service():
            ## create transaction
            transaction = reputation.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + reputation_contract.contract_name
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])



    # --------------------------------------------------------------
    # test create reputation voting
    # --------------------------------------------------------------
    def test_create_reputation(self):
        with reputation_contract.test_service():
            ## create transaction
            # init
            init_transaction = reputation.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise reputation voting
            transaction = reputation.create_reputation(
                (token,),
                None,
                None,
                UUID,
                options,
                sk_owners[0],
                aggr_pk_owner,
                t_owners,
                n_owners,
                aggr_vk,
                merchant_vk
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + reputation_contract.contract_name
                + '/create_reputation', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

 
    # --------------------------------------------------------------
    # test sign
    # --------------------------------------------------------------
    def test_sign(self):
        with reputation_contract.test_service():
            # create transaction
            # init
            init_transaction = reputation.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise reputation voting
            create_reputation_transaction = reputation_contract.create_reputation(
                (token,),
                None,
                None,
                UUID,
                options,
                sk_owners[0],
                aggr_pk_owner,
                t_owners,
                n_owners,
                aggr_vk,
                merchant_vk
            )
            old_reputation = create_reputation_transaction['transaction']['outputs'][1]
            old_list = create_reputation_transaction['transaction']['outputs'][2]

            # reading the material for the credential and bill verification
            # -----------------------------------
            item_sign = unpack(readkey('signature2.txt'))
            bill_number = unpack(readkey('bill_number.txt'))
            # add signature to the reputation voting

            transaction = reputation.sign(
                (old_reputation, old_list),
                None,
                None,
                d,
                sigma,
                aggr_vk,
                item_sign,
                merchant_vk,
                bill_number,
                0
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + reputation_contract.contract_name
                + '/sign', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])


    # --------------------------------------------------------------
    # test tally
    # --------------------------------------------------------------
    def test_tally(self):
        with reputation_contract.test_service():
            # create transaction
            # init
            init_transaction = reputation.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise reputation voting
            create_reputation_transaction = reputation_contract.create_reputation(
                (token,),
                None,
                None,
                UUID,
                options,
                sk_owners[0],
                aggr_pk_owner,
                t_owners,
                n_owners,
                aggr_vk,
                merchant_vk
            )
            old_reputation = create_reputation_transaction['transaction']['outputs'][1]
            old_list = create_reputation_transaction['transaction']['outputs'][2]

            # add signature to the reputation voting
            for i in range(3):
                # reading material to credential and bill verification
                # ------------------------------------
                item_sign = unpack(readkey('signature2.txt'))
                #bill_number = sha1(b"Hello Worldsss!").digest()
                bill_number = unpack(readkey('bill_number.txt'))
                sign_transaction = reputation.sign(
                    (old_reputation, old_list),
                    None,
                    None,
                    d,
                    sigma,
                    aggr_vk,
                    item_sign,
                    merchant_vk,
                    bill_number,
                    0 # vote
                )
                old_reputation = sign_transaction['transaction']['outputs'][0]
                old_list = sign_transaction['transaction']['outputs'][1]

            # tally
            for i in range(t_owners):
                transaction = reputation.tally(
                    (old_reputation,),
                    None,
                    None,
                    sk_owners[i],
                    i,
                    t_owners
                )
                old_reputation = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + reputation_contract.contract_name
                + '/tally', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])


    # --------------------------------------------------------------
    # test read
    # --------------------------------------------------------------
    def test_read(self):
        with reputation_contract.test_service():
            # create transaction
            # init
            init_transaction = reputation.init()
            token = init_transaction['transaction']['outputs'][0]

            # initialise reputation voting
            create_reputation_transaction = reputation.create_reputation(
                (token,),
                None,
                None,
                UUID,
                options,
                sk_owners[0],
                aggr_pk_owner,
                t_owners,
                n_owners,
                aggr_vk,
                merchant_vk
            )
            old_reputation = create_reputation_transaction['transaction']['outputs'][1]
            old_list = create_reputation_transaction['transaction']['outputs'][2]

            # add signature to the reputation voting
            for i in range(3):
                # material to validate the credential
                # ------------------------------------
                (d, gamma) = elgamal_keygen(bp_params)
                private_m = [d]
                # ------------------------------------
                item_sign = unpack(readkey('signature.txt'))
                #bill_number = sha1(b"Hello Worldsss!").digest()
                bill_number = unpack(readkey('bill_number.txt'))
                sign_transaction = reputation.sign(
                    (old_reputation, old_list),
                    None,
                    None,
                    d,
                    sigma,
                    aggr_vk,
                    item_sign,
                    merchant_vk,
                    bill_number,
                    0 # vote
                )
                old_reputation = sign_transaction['transaction']['outputs'][0]
                old_list = sign_transaction['transaction']['outputs'][1]

            # tally
            for i in range(t_owners):
                transaction = reputation.tally(
                    (old_reputation,),
                    None,
                    None,
                    sk_owners[i],
                    i,
                    t_owners
                )
                old_reputation = transaction['transaction']['outputs'][0]


            # read
            transaction = reputation.read(
                None,
                (old_reputation,),
                None
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + reputation_contract.contract_name
                + '/read', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            print("\n\n==================== OUTCOME ====================\n")
            print('OUTCOME: ', loads(transaction['transaction']['returns'][0]))
            print("\n===================================================\n\n")

   
####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
