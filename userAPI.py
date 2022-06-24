#!/usr/bin/env python3

from flask import Flask
from flask import request
from os import environ
import boto3


# initialize Flask client
app = Flask(__name__)

# initializing client w/ boto3
client = boto3.client("cognito-idp", region_name="us-east-2")

@app.route("/signup", methods=['POST'])
def sign_up():
    print(request.form)
    return client.sign_up(ClientId=environ["COGNITO_CLIENT_ID"],
                    Username=request.json["user"],
                    Password=request.json["pass"])


app.run("0.0.0.0", 3000, load_dotenv=True)
