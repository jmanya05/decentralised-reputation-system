# flask server
from json  import loads, dumps
from flask import Flask, request
# url parser
from urllib.parse import urlparse

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

@app.route("/info-purchasing", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        option = request.form.get('foption')
        print(option)

        if option == '1':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1001<br>
                    Description: Fishing Rod<br>
                    SKU: FI-R01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)
        if option == '2':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1002<br>
                    Description: Fishing Hooks<br>
                    SKU: FI-R01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)
        if option == '3':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1003<br>
                    Description: Boat<br>
                    SKU: FI-B01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)
        if option == '4':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1004<br>
                    Description: Tent<br>
                    SKU: CA-T01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)
        if option == '5':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1005<br>
                    Description: Stove<br>
                    SKU: CA-S01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)
        if option == '6':
            bill_number = [random.randint(0,1000000) for _ in range(1)]
            return '''<form action="/info-purchasing" method="POST">
                    <h2>Thank you for your purchase</h2>
                    <p>Here you have the information of your purchasing:</p>
                    Your item selected: 1006<br>
                    Description: 4x4 car<br>
                    SKU: EX-C01<br>
                    Bill Number: {}
                  </form>'''.format(bill_number)

    return '<h1>Your option is invalid</h1>'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user')
        pswd = request.form['pswd']

        user1 = "jorge.manya.18@ucl.ac.uk"
        pswd1 = "1234"

        user2 = "alberto.sonnino@ucl.ac.uk"
        pswd2 = "abcd"

        if (user == user1 and pswd == pswd1) or ((user == user2 and pswd == pswd2)):
            return render_products()

        return '<h1>User or password invalid</h1>'

    return '''<form method="POST">
                  <h2>Welcome to Adventurous Life Store</h2>
                  <p>Please insert yout credentials:</p>
                  Email: <input type="text" name="user"><br>
                  Password: <input type="password" name="pswd" maxlength="8"><br>
                  <input type="reset" value="Reset">
                  <input type="submit">
              </form>'''

if __name__ == "__main__":
        app.run(host="0.0.0.0", port=80)
