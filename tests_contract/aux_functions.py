from petlib.pack import encode, decode
from binascii import hexlify, unhexlify
from json import dump
from tempfile import mkstemp
from shutil import move
from os import remove, close


def pack(x):
    return hexlify(encode(x)).decode('utf-8')

def unpack(x):
    return decode(unhexlify(x.encode('utf-8')))

def savekey(file, variable):
        with open(file, 'w') as file:
#                file.write('[')
                for i in range(len(variable)):
                        file.write(variable[i])
    ##            file.write(']')

def readkey(file):
     key = open(file, 'r')
     return key.read()

