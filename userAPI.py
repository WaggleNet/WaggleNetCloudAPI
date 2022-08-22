#!/usr/bin/env python3

from flask import Flask
from flask import request
from os import environ
import boto3


# initialize Flask client
app = Flask(__name__)
# initializing client w/ boto3
client = boto3.client("cognito-idp", region_name="us-east-2")

@app.route("/signUp", methods=['POST'])
def sign_up():
    # TODO - sanitize signup paramaters
    #   - check for valid email and password
    #   - Exception behavior
    if request.authorization is None or request.authorization.username \
       is None or request.authorization.password is None:
        return "Authorization header not supplied", 400

    return client.sign_up(ClientId=environ["COGNITO_CLIENT_ID"],
                    Username=request.authorization.username,
                     Password=request.authorization.password)

@app.route("/confirm", methods=['POST'])
def confirm():
    if request.json is None:
        return "No JSON load supplied", 400

    if not ("user" in request.json.keys() and "code" in request.json.keys()):
        return "Required fields not supplied", 400

    # TODO - validate if username is an email. Make helper function for this?

    try:
        return client.confirm_sign_up(ClientId=environ["COGNITO_CLIENT_ID"],
                                Username=request.json["user"],
                                ConfirmationCode=str(request.json["code"]))
    except Exception:
        return "Uncaught internal server error", 400

@app.route("/resend", methods=["POST"])
def resend():
    if request.json is None:
        return "No JSON load supplied", 400

    if "user" not in request.json.keys():
        return "username not supplied", 400

    try:
        return client.resend_confirmation_code(ClientId=environ["COGNITO_CLIENT_ID"],
                                        Username=request.json["user"])
    except:
        return "Uncaught internal server error", 400

@app.route("/signIn", methods=["POST"])
def signIn():
    # TODO - validate/sanitize username and password
    if request.authorization is None or request.authorization.username \
       is None or request.authorization.password is None:
        return "Authorization header not supplied", 400

    try:
        response =  client.initiate_auth(ClientId=environ["COGNITO_CLIENT_ID"],
                                AuthFlow="USER_PASSWORD_AUTH",
                                AuthParameters={"USERNAME": request.authorization.username,
                                                "PASSWORD": request.authorization.password})

        print(response.keys())
        return {k:response["AuthenticationResult"][k] for k in ("AccessToken", "IdToken")}
    except client.exceptions.NotAuthorizedException:
        return "Incorrect username or password", 401

app.run("0.0.0.0", 3000, load_dotenv=True)
