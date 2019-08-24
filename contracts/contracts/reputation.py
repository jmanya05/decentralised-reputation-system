""" 
	This is an Smart Contract for a Decentralised Reputation System.
"""


####################################################################
# imports
####################################################################
# general
from hashlib import sha256, sha1
from json    import dumps, loads
# petlib
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.ec import EcGroup
# coconut
from chainspacecontract.examples.utils import *
from chainspacecontract.examples.reputation_proofs import *
from chainspacecontract.examples.aux_functions import readkey, pack, unpack, savekey
from chainspacecontract.examples.utils import setup as pet_setup
from coconut.utils import *
from coconut.scheme import *


# chainspace
from chainspacecontract import ChainspaceContract

## contract name
contract = ChainspaceContract('reputation')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'PToken'}),),
    }

# ------------------------------------------------------------------
# create reputation voting
# ------------------------------------------------------------------
@contract.method('create_reputation')
def create_reputation(inputs, reference_inputs, parameters, UUID, options, priv_owner, pub_owner,
    t_owners, n_owners, aggr_vk, merchant_vk):
    # inital score
    pet_params = pet_setup()
    (G, g, hs, o) = pet_params
    zero = (G.infinite(), G.infinite())
    scores = [pack(zero), pack(zero)]

    # new reputation voting object
    new_reputation = {
        'type' : 'PObject',
        'UUID' : pack(UUID), # unique ID of the reputation voting
        't_owners' : t_owners,
        'n_owners' : n_owners,
        'owner' : pack(pub_owner), # entity creating the reputation voting
        'verifier' : pack(aggr_vk), # Authoritie's aggregate keys
        'merchant_vk' : pack(merchant_vk),
        'options' : options, # options to vote for an item
        'scores' : scores, # the signatures per vote
        'dec' : []  # holds decryption shares
    }

    # ID lists
    signed_list = {
        'type' : 'PList',
        'list' : []
    }

    # signature: this should be be signed by the owners
    #hasher = sha256()
    #hasher.update(dumps(new_reputation).encode('utf8'))
    #sig = do_ecdsa_sign(pet_params[0], priv_owner, hasher.digest())

    # return
    return {
        'outputs': (inputs[0], dumps(new_reputation), dumps(signed_list)),
        #'extra_parameters' : (pack(sig),)
    }

# ------------------------------------------------------------------
# sign
# ------------------------------------------------------------------
@contract.method('sign')
def sign(inputs, reference_inputs, parameters, priv_signer, sig, aggr_vk, item_sign, merchant_vk, bill, vote):
    # get reputation and list
    old_reputation = loads(inputs[0])
    new_reputation = loads(inputs[0])
    old_list = loads(inputs[1])
    new_list = loads(inputs[1])

    # prepare showing of credentials
    UUID = unpack(old_reputation['UUID'])
    bp_params = setup()
    (kappa, nu, sigma, zeta, pi_reputation) = make_proof_credentials_reputation(bp_params, aggr_vk, sig, [priv_signer], UUID)

    #assert verify_proof_credentials_reputation(bp_params, aggr_vk, sig, kappa, nu, zeta, pi_reputation, UUID)

    # prepare showing of signature
    signature = item_sign
    merchant_ver_key = merchant_vk
    bill_number = bill
    # update spent list
    new_list['list'].append(pack(zeta))

    # encrypt the votes 
    pub_owner = unpack(old_reputation['owner'])
    pet_params = pet_setup()
    (enc_v, enc_v_not, cv, pi_vote) = make_proof_vote_reputation(pet_params, pub_owner, vote)
    #assert verify_proof_vote_reputation(pet_params, enc_v, pub_owner, cv, pi_vote)

    # update reputation values
    old_enc_v = unpack(old_reputation['scores'][0])
    old_enc_v_not = unpack(old_reputation['scores'][1])
    new_enc_v = (old_enc_v[0] + enc_v[0], old_enc_v[1] + enc_v[1])
    new_enc_v_not = (old_enc_v_not[0] + enc_v_not[0], old_enc_v_not[1] + enc_v_not[1])
    new_reputation['scores'] = [pack(new_enc_v), pack(new_enc_v_not)]

    # return
    return {
        'outputs': (dumps(new_reputation),dumps(new_list)),
        'extra_parameters' : (pack(sigma), pack(kappa), pack(nu), pack(zeta), pack(pi_reputation),
            pack(enc_v), pack(cv), pack(pi_vote), pack(signature), pack(merchant_ver_key), pack(bill_number))
    }

# ------------------------------------------------------------------
# tally
# ------------------------------------------------------------------
@contract.method('tally')
def tally(inputs, reference_inputs, parameters, tally_priv, index, t_owners):
    # load reputation & scores
    reputation = loads(inputs[0])
    enc_results = [unpack(reputation['scores'][0]), unpack(reputation['scores'][1])]

    # decrypt results
    pet_params = pet_setup()
    (G, g, hs, o) = pet_params
    l = lagrange_basis(range(1,t_owners+1), o, 0)
    dec_share = [(-tally_priv*l[index]*enc[0]) for enc in enc_results]
    reputation['dec'].append(pack(dec_share))

    ## proof of correct decryption
    pi_tally = make_proof_tally_reputation(pet_params, l[index], enc_results, tally_priv)
    #assert verify_proof_tally_reputation(pet_params, l[index], enc_results, pi_tally, dec_share)
    
    # return
    return {
        'outputs': (dumps(reputation),),
        'extra_parameters' : (pack(dec_share), pack(pi_tally), dumps(index))
    }

# ------------------------------------------------------------------
# read
# ------------------------------------------------------------------
@contract.method('read')
def read(inputs, reference_inputs, parameters):
    reputation = loads(reference_inputs[0])
    enc_results = [unpack(reputation['scores'][0]), unpack(reputation['scores'][1])]

    # add decryption shares
    pet_params = pet_setup()
    (G, g, hs, o) = pet_params
    (dec_v, dec_v_not) = (G.infinite(), G.infinite())
    for packed_share in reputation['dec']:
        dec_share = unpack(packed_share)
        dec_v += dec_share[0]
        dec_v_not += dec_share[1]

    # decrypt
    table = {}
    for i in range(-1000, 1000): table[i * hs[0]] = i
    plain_v = enc_results[0][1] + dec_v
    plain_v_not = enc_results[1][1] + dec_v_not

    # outcome
    outcome = {
        reputation['options'][0]: table[plain_v],
        reputation['options'][1]: table[plain_v_not]
    }

    # return
    return {
        'returns': (dumps(outcome),),
    }


####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check reputation voting creation
# ------------------------------------------------------------------
@contract.checker('create_reputation')
def create_reputation_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve inputs
        reputation = loads(outputs[1])
        spent_list = loads(outputs[2])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 3 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'PToken' or loads(outputs[0])['type'] != 'PToken': return False
        if reputation['type'] != 'PObject' or spent_list['type'] != 'PList': return False

        # check fields
        reputation['UUID'] # check presence of field
        reputation['verifier'] # check presence of field
        reputation['merchant_vk']
        reputation['t_owners'] # check presence of field
        reputation['n_owners'] # check presence of field
        options = reputation['options']
        scores = reputation['scores']
        pub_owner = unpack(reputation['owner'])
        if len(options) < 1 or len(options) != len(scores): return False

        # check initalised scores
        pet_params = pet_setup()
        (G, g, hs, o) = pet_params
        zero = (G.infinite(), G.infinite())
        if not all(init_score==pack(zero) for init_score in scores): return False

        # verify signature
        #hasher = sha256()
        #hasher.update(outputs[1].encode('utf8'))
        #sig = unpack(parameters[0])
        #if not do_ecdsa_verify(pet_params[0], pub_owner, sig, hasher.digest()): return False

        # verify that the spent list & results store are empty
        if spent_list['list'] or reputation['dec']: return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False


# ------------------------------------------------------------------
# check sign
# ------------------------------------------------------------------
@contract.checker('sign')
def sign_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve reputation voting
        old_reputation = loads(inputs[0])
        new_reputation = loads(outputs[0])
        # retrieve ID list
        old_list = loads(inputs[1])
        new_list = loads(outputs[1])
        # retrieve parameters
        bp_params = setup()
        sig = unpack(parameters[0])
        kappa = unpack(parameters[1])
        nu = unpack(parameters[2])
        zeta = unpack(parameters[3])
        pi_reputation = unpack(parameters[4])
        enc_v = unpack(parameters[5])
        cv = unpack(parameters[6])
        pi_vote = unpack(parameters[7])
        signature = unpack(parameters[8])
        merchant_ver_key = unpack(parameters[9])
        bill_number = unpack(parameters[10])

        
        # check format
        if len(inputs) != 2 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if new_reputation['type'] != 'PObject' or new_list['type'] != 'PList': return False

        # check format & consistency with old object
        UUID = unpack(new_reputation['UUID'])
        options = new_reputation['options']
        packed_vk = new_reputation['verifier']
        #packed_merchant_vk = new_reputation['merchant_vk']
        scores = new_reputation['scores']
        if old_reputation['UUID'] != new_reputation['UUID']: return False
        if old_reputation['owner'] != new_reputation['owner']: return False
        if old_reputation['options'] != new_reputation['options']: return False
        if old_reputation['verifier'] != new_reputation['verifier']: return False
        if old_reputation['merchant_vk'] != new_reputation['merchant_vk']: return False
        if old_reputation['t_owners'] != new_reputation['t_owners']: return False
        if old_reputation['n_owners'] != new_reputation['n_owners']: return False

        # re-compute opposite of vote encryption
        pet_params = pet_setup()
        (G, g, hs, o) = pet_params
        (a, b) = enc_v
        enc_v_not = (-a, -b + hs[0])

        # check homomorphic add
        old_enc_v = unpack(old_reputation['scores'][0])
        old_enc_v_not = unpack(old_reputation['scores'][1])
        new_enc_v = (old_enc_v[0] + enc_v[0], old_enc_v[1] + enc_v[1])
        new_enc_v_not = (old_enc_v_not[0] + enc_v_not[0], old_enc_v_not[1] + enc_v_not[1])
        if not new_reputation['scores'] == [pack(new_enc_v), pack(new_enc_v_not)]: return False

        # check new values
        pub_owner = unpack(old_reputation['owner'])
        if not  verify_proof_vote_reputation(pet_params, enc_v, pub_owner, cv, pi_vote): return False

        # check double-voting list
        packed_zeta = parameters[3]
        if (packed_zeta in old_list['list']) or (new_list['list'] != old_list['list'] + [packed_zeta]):
            return False
        
        # verify coconut credentials
        aggr_vk = unpack(packed_vk)
        if not verify_proof_credentials_reputation(bp_params, aggr_vk, sig, kappa, nu, zeta, pi_reputation, UUID):
            return False

        # verify merchant bill
        G = EcGroup()
        if not do_ecdsa_verify(G, merchant_ver_key, signature, bill_number):
            return False

        # otherwise
        return True

    except (KeyError, Exception): 
        return False

# ------------------------------------------------------------------
# check tally
# ------------------------------------------------------------------
@contract.checker('tally')
def tally_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        old_reputation = loads(inputs[0])
        new_reputation = loads(outputs[0])
        dec_share = unpack(parameters[0])
        pi_tally = unpack(parameters[1])
        index = loads(parameters[2])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 

        # check types
        if old_reputation['type'] != new_reputation['type']: return False

        # check fields consistency
        if old_reputation['UUID'] != new_reputation['UUID']: return False
        if old_reputation['owner'] != new_reputation['owner']: return False
        if old_reputation['options'] != new_reputation['options']: return False
        if old_reputation['verifier'] != new_reputation['verifier']: return False
        if old_reputation['t_owners'] != new_reputation['t_owners']: return False
        if old_reputation['n_owners'] != new_reputation['n_owners']: return False
        if old_reputation['scores'] != new_reputation['scores']: return False

        # check fields
        if new_reputation['dec'] != old_reputation['dec'] + [parameters[0]]: return False
        
        ## verify proof of tally
        pet_params = pet_setup()
        (G, g, hs, o) = pet_params
        enc_results = [unpack(old_reputation['scores'][0]), unpack(old_reputation['scores'][1])]
        t_owners = new_reputation['t_owners']
        l = lagrange_basis(range(1,t_owners+1), o, 0)
        if not verify_proof_tally_reputation(pet_params, l[index], enc_results, pi_tally, dec_share): return False

        # otherwise
        return True

    except (KeyError, Exception): 
        return False


# ------------------------------------------------------------------
# check read
# ------------------------------------------------------------------
@contract.checker('read')
def read_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # check format
        if len(inputs) != 0 or len(reference_inputs) != 1 or len(outputs) != 0 or len(returns) != 1:
            return False 

        # otherwise
        return True

    except (KeyError, Exception): 
        return False


####################################################################
# main
####################################################################
if __name__ == '__main__':
    contract.run()



####################################################################
