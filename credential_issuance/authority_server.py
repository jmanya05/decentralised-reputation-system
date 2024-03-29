##########################################
# Each server for signing
#
# version: 2.1.4
##########################################

import sys

# flask
from json  import loads, dumps
from flask import Flask, request

# url parser
from urllib.parse import urlparse
import pickle
import json

# coconut
from bplib.bp import BpGroup, G2Elem
from coconut.scheme import *

# standard REST lib
from json import loads, dumps, dump

# async REST lib
import asyncio
import concurrent.futures
import requests
#import grequests

# timing & db
import time

#from tinydb import TinyDB, Query
from aux_functions import pack, unpack, savekey, readkey

##########################################

# static fields
server_id = 'Authority5'
SECRET_KEY = 'secret_key.txt'
PUBLIC_KEY = 'public_key.txt'
q = 7

# crypto
params = setup()

# make packet for client
def format(load):
        return dumps({
                "status": "OK",
                "machine_id": server_id,
                "load": load
        })

##########################################
# server functions
##########################################
def sign_wrapper(data):
        m = data["message"]
        app.sk = unpack(readkey(SECRET_KEY))
        sig = sign(params, app.sk, m)
        return format(pack(sig))

def blind_sign_wrapper(data):
    cm = unpack(data["cm"])
    c = unpack(data["c"])
    proof_s = unpack(data["proof_s"])
    gamma = unpack(data["gamma"])
    Lambda = (cm, c, proof_s)
#    public_m = unpack(data["public_m"])
    app.sk = unpack(readkey(SECRET_KEY))
    blind_sig = blind_sign(params, app.sk, gamma, Lambda)
    return format(pack(blind_sig))

##########################################
# webapp
##########################################

app = Flask(__name__)

#app.sk = None

# ----------------------------------------
# /sign/public
# return basic info about the server
# ----------------------------------------

@app.route("/", methods=["GET", "POST"])

def index():
        return dumps({"status": "OK", "key": readkey(PUBLIC_KEY)})
# ----------------------------------------
# /key/set
# Set Keys on each authority
# --------------------------------------- method."})

@app.route("/key/set", methods=["GET", "POST"])

def key_set():
        if request.method == "POST":
                try:
                        data = loads(request.data.decode('utf-8'))
                        app.sk = unpack(data["sk"])
                        savekey(PUBLIC_KEY, data["vk"])
                        savekey(SECRET_KEY, data["sk"])
                        return dumps({"status": "OK", "message":
                        'Hello I am server '+server_id+' and this is my public key '+data["vk"]})
                except KeyError as e:
                        return dumps({"status": "ERROR", "message": e.args})
                except Exception as e:
                        return dumps({"status": "ERROR", "message": e.args})
        else:
                return dumps({"status": "ERROR", "message":"Use POST method."})

# ----------------------------------------
# /sign/public
# request a signature on a public attribute
# ----------------------------------------

@app.route("/sign/public", methods=["GET", "POST"])

def sign_public():
        if request.method == "POST":
                try:
                        return sign_wrapper(loads(request.data.decode("utf-8")))
                except KeyError as e:
                        return dumps({"status": "ERROR", "message": e.args})
                except Exception as e:
                        return dumps({"status": "ERROR", "message": e.args})
        else:
                return dumps({"status": "ERROR", "message":"Use POST method."})

# ----------------------------------------
# /sign/cred
# request a signature on a private attribute
# ----------------------------------------

@app.route("/sign/cred", methods=["GET", "POST"])

def sign_private():
        if request.method == "POST":
                try:
                        return blind_sign_wrapper(loads(request.data.decode("utf-8")))
                except KeyError as e:
                        return dumps({"status": "ERROR", "message": e.args})
                except Exception as e:
                        return dumps({"status": "ERROR", "message": e.args})
        else:
                return dumps({"status": "ERROR", "message":"Use POST method."})

##########################################
# program entry point
##########################################

if __name__ == "__main__":
        #port = int(sys.argv[1])
        #server_id = port
        app.run(host="0.0.0.0", port=80, debug=True)

##########################################


