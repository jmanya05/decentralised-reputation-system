# flask server
from json import loads, dumps
from flask import Flask, request, send_file, render_template
# url parser
from urllib.parse import urlparse
#utilities
import sys
import hashlib
from aux_functions import readkey, savekey, pack, unpack
from hashlib import sha1, sha256
#petlib
from petlib.ec import EcGroup
from petlib.ecdsa import  do_ecdsa_sign, do_ecdsa_verify

import requests
import asyncio
import concurrent.futures
import sys
import time
import random
import getpass

# webapp
app = Flask(__name__)
app.sk = None

def render_products():
    return '''
<h2>Successful Login</h2>
<p>Please choose an OPTION:</p>

<table style="border: 1px solid black;">
  <tr>
    <th style="border: 1px solid black;">Option</th>
    <th style="border: 1px solid black;">ID</th>
    <th style="border: 1px solid black;">Item</th>
    <th style="border: 1px solid black;">Section</th>
    <th style="border: 1px solid black;">SKU</th>
    <th style="border: 1px solid black;">Price (£)</th>
    <th style="border: 1px solid black;">Stock</th>
  </tr>
  <tr>
    <td style="border: 1px solid black;">1</td>
    <td style="border: 1px solid black;">1001</td>
    <td style="border: 1px solid black;">Fishing Rod</td>
    <td style="border: 1px solid black;">Fishing</td>
    <td style="border: 1px solid black;">FI-R01</td>
    <td style="border: 1px solid black;">30</td>
    <td style="border: 1px solid black;">2</td>
  </tr>
  <tr>
    <td style="border: 1px solid black;">2</td>
    <td style="border: 1px solid black;">1002</td>
    <td style="border: 1px solid black;">Fishing Hooks</td>
    <td style="border: 1px solid black;">Fishing</td>
    <td style="border: 1px solid black;">FI-H01</td>
    <td style="border: 1px solid black;">1</td>
    <td style="border: 1px solid black;">20</td>
  </tr>
  <tr>
    <td style="border: 1px solid black;">3</td>
    <td style="border: 1px solid black;">1003</td>
    <td style="border: 1px solid black;">Boat</td>
    <td style="border: 1px solid black;">Fishing</td>
    <td style="border: 1px solid black;">FI-B01</td>
    <td style="border: 1px solid black;">200</td>
    <td style="border: 1px solid black;">3</td>
  </tr>
  <tr>
    <td style="border: 1px solid black;">4</td>
    <td style="border: 1px solid black;">1004</td>
    <td style="border: 1px solid black;">Tent</td>
    <td style="border: 1px solid black;">Camping</td>
    <td style="border: 1px solid black;">CA-T01</td>
    <td style="border: 1px solid black;">40</td>
    <td style="border: 1px solid black;">5</td>
  </tr>
  <tr>
    <td style="border: 1px solid black;">5</td>
    <td style="border: 1px solid black;">1005</td>
    <td style="border: 1px solid black;">Stove</td>
    <td style="border: 1px solid black;">Camping</td>
    <td style="border: 1px solid black;">CA-S01</td>
    <td style="border: 1px solid black;">40</td>
    <td style="border: 1px solid black;">7</td>
  </tr>
  <tr>
    <td style="border: 1px solid black;">6</td>
    <td style="border: 1px solid black;">1006</td>
    <td style="border: 1px solid black;">4x4 Car</td>
    <td style="border: 1px solid black;">Exploring</td>
    <td style="border: 1px solid black;">EX-C01</td>
    <td style="border: 1px solid black;">20000</td>
    <td style="border: 1px solid black;">2</td>
  </tr>
</table>
<form action="/info-purchasing" method="post">
  Option: <input type="text" name="foption"><br>
  <button type="submit">Submit</button><br>
</form>
'''

def data():
    option = request.form.get('foption')

    #bill_number = [random.randint(0,10000)]
    #bill_number = sha1(b'bill_number').digest()
    bill_number = str(random.randint(1, 10000))
    bill_hashed = hashlib.sha256(bill_number.encode('utf-8')).digest()
    G = unpack(readkey('group.txt'))[0]
    sig_key = unpack(readkey('sig_key.txt'))
    ver_key = unpack(readkey('ver_key.txt'))
    time.sleep(3)
     # Sign and verify signature
    sig = do_ecdsa_sign(G, sig_key, bill_hashed)
    assert do_ecdsa_verify(G, ver_key, sig, bill_hashed)
    return(option, bill_number, ver_key, bill_hashed, sig)


@app.route("/info-purchasing", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        #option = request.form.get('foption')
        #print ("OPTION:",option)
        (option, bill_number, ver_key, bill_hashed, sig) = data()
        pack_bill_hashed = pack(bill_hashed)
        pack_sig = pack(sig)
        pack_verkey = pack(ver_key)

        filedata = open("data_contract.txt","w")
        filedata.write(pack_sig)
        filedata.write("\n")
        filedata.write(pack_bill_hashed)
        filedata.close()

        if option == '1':
            return '''<form action="/data_contract" method="POST">
                   <h2>Thank you for your purchase</h2>
                   <p>Here you have the information of your purchasing:</p>
                   Your item selected: 1001<br>
                   Description: Fishing Rod<br>
                   SKU: FI-R01<br>
                   Bill Number: {} <br>
                   Bill Number SHA-256 HASH: {} <br>
                   SIGNATURE: {} <br>
                   <h2>Customer Satisfaction Scores </h2>
                   <p> Your opinion is important, on scale of 0 or 1, <p>
                   <p> How would you rate your overall satisfaction with the item you bought? </p>
                   <p> 0 - Dissatisfied / 1 - Satisfied <p>
                   <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                   Rate: <input type="text" name="frate"><br>
                   <button type="submit">Submit</button><br>
                   </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

        if option == '2':
            return '''<form action="/data_contract" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1002<br>
                    Description: Fishing Hooks<br>
                    SKU: FI-R01<br>
                    Bill Number: {} <br>
                    Bill Number SHA-256 HASH: {} <br>
                    SIGNATURE: {}<br>
                    <h2>Customer Satisfaction Scores </h2>
                    <p> Your opinion is important, on scale of 0 or 1, <p>
                    <p> How would you rate your overall satisfaction with the item you bought? </p>
                    <p> 0 - Dissatisfied / 1 - Satisfied <p>
                    <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                    Rate: <input type="text" name="frate"><br>
                    <button type="submit">Submit</button><br>
                    </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

        if option == '3':
            return '''<form action="/data_contract" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1003<br>
                    Description: Boat<br>
                    SKU: FI-B01<br>
                    Bill Number: {} <br>
                    Bill Number SHA-256 HASH: {} <br>
                    SIGNATURE: {} <br>
                    <h2>Customer Satisfaction Scores </h2>
                    <p> Your opinion is important, on scale of 0 or 1, <p>
                    <p> How would you rate your overall satisfaction with the item you bought? </p>
                    <p> 0 - Dissatisfied / 1 - Satisfied <p>
                    <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                    Rate: <input type="text" name="frate"><br>
                    <button type="submit">Submit</button><br>
                    </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

        if option == '4':
            return '''<form action="/data_contract" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1004<br>
                    Description: Tent<br>
                    SKU: CA-T01<br>
                    Bill Number: {} <br>
                    Bill Number SHA-256 HASH: {} <br>
                    SIGNATURE: {} <br>
                    <h2>Customer Satisfaction Scores </h2>
                    <p> Your opinion is important, on scale of 0 or 1, <p>
                    <p> How would you rate your overall satisfaction with the item you bought? </p>
                    <p> 0 - Dissatisfied / 1 - Satisfied <p>
                    <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                    Rate: <input type="text" name="frate"><br>
                    <button type="submit">Submit</button><br>
                    </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

        if option == '5':
            return '''<form action="/data_contract" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1005<br>
                    Description: Stove<br>
                    SKU: CA-S01<br>
                    Bill Number: {} <br>
                    Bill Number SHA-256 HASH: {} <br>
                    SIGNATURE: {} <br>
                    <h2>Customer Satisfaction Scores </h2>
                    <p> Your opinion is important, on scale of 0 or 1, <p>
                    <p> How would you rate your overall satisfaction with the item you bought? </p>
                    <p> 0 - Dissatisfied / 1 - Satisfied <p>
                    <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                    Rate: <input type="text" name="frate"><br>
                    <button type="submit">Submit</button><br>
                    </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

        if option == '6':
            return '''<form action="/data_contract" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1006<br>
                    Description: 4x4 car<br>
                    SKU: EX-C01<br>
                    Bill Number: {} <br>
                    Bill Number SHA-256 HASH: {} <br>
                    SIGNATURE: {} <br>
                    <h2>Customer Satisfaction Scores </h2>
                    <p> Your opinion is important, on scale of 0 or 1, <p>
                    <p> How would you rate your overall satisfaction with the item you bought? </p>
                    <p> 0 - Dissatisfied / 1 - Satisfied <p>
                    <p> After hitting SUBMIT, you will receive some data that will allow you to vote. Please, save such information in a .txt file. </p>
                    Rate: <input type="text" name="frate"><br>
                    <button type="submit">Submit</button><br>
                    </form>'''.format(bill_number, pack(bill_hashed), pack(sig))

    return '<h1>Your option is invalid</h1>'

@app.route('/data_contract', methods = ["GET","POST"])
def return_file():
    if request.method == 'POST':
       rate = request.form.get('frate')

       filedata = open("data_contract.txt","a")
       filedata.write("\n")
       filedata.write(rate)
       filedata.close()
       if (rate == '0' or rate == '1'):
           return send_file('/home/ubuntu/coconut/data_contract.txt', attachment_filename = 'data_contract.txt')

    return '<h1>The rate must be 0 or 1</h1>'

@app.route('/', methods=['GET', 'POST'])
def login():
    unverkey = unpack(readkey('ver_key.txt'))
    print (unverkey)

    if request.method == 'POST':
        user = request.form.get('user')
        pswd = request.form['pswd']

        user1 = "jorge.manya.18@ucl.ac.uk"
        pswd1 = "wx5VMPmI"

        user2 = "alberto.sonnino@ucl.ac.uk"
        pswd2 = "fAIeZRPu"


        if (user == user1 and pswd == pswd1) or ((user == user2 and pswd == pswd2)):
            return render_products()

        return '<h1>User or password invalid...</h1>'

    return '''<form method="POST">
                  <h2>Welcome to Adventurous Life Store</h2>
                  Server's public key: {} <br>
                  <p>Please insert your credentials:</p>
                  Email: <input type="text" name="user"><br>
                  Password: <input type="password" name="pswd" maxlength="8"><br>
                  <input type="reset" value="Reset">
                  <input type="submit">
              </form>'''.format(pack(unverkey))


if __name__ == "__main__":
    #port = int(sys.argv[1])
    #server_id = port
    app.run(host="0.0.0.0", port=80)
