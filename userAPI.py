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
    # TODO - sanitize signup paramaters
    #   - check for valid email and password
    return client.sign_up(ClientId=environ["COGNITO_CLIENT_ID"],
                    Username=request.json["user"],
                    Password=request.json["pass"])

@app.route("/confirm", methods=['POST'])
def confirm():

    if request.json is None:
        return "No JSON load supplied", 400


    if not ("user" in request.json.keys() and "code" in request.json.keys()):
        return "Required fields not supplied", 400

    return client.confirm_sign_up(ClientId=environ["COGNITO_CLIENT_ID"],
                             Username=request.json["user"],
                             ConfirmationCode=request.json["code"])


app.run("0.0.0.0", 3000, load_dotenv=True)
