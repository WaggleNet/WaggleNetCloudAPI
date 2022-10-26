#!/usr/bin/env python3

from flask import Flask
from flask import request
from os import environ
import boto3
import re

# initialize Flask client
app = Flask(__name__)
# initializing client w/ boto3
client = boto3.client("cognito-idp", region_name="us-east-2")

# validating email
# Make a regular expression
# for validating an Email
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

def checkemail(email):
    if not (re.fullmatch(regex, email)):
        return "Invalid email", 400

# validating password
# Password must have 8 chars minimum, >=1 uppercase letter, >=1 number, >=1 special symbol. A character can be consecutively repeated a maximum of 2 times.
def checkpwd(pwd):
    print("hello")
    # check for pwd length
    if len(pwd) < 8:
        return "Invalid password, password must have 8 characters minimum", 400
    upper = False
    dig = False
    for elem in pwd:
        # check for uppercase char
        if elem.isupper():
            upper = True
            break
        # check for number
        if elem.isdigit():
            dig = True
            break
    if not upper == True:
        return "Invalid password, password must contain at least 1 uppercase character", 400
    if not dig == True:
        return "Invalid password, password must contain at least 1 number", 400
    # check for special char
    special_characters = "[@_!#$%^&*()<>?/\|}{~:]"
    if not any(c in special_characters for c in pwd):
        return "Invalid password, password must contain at least 1 special character", 400
    # check if consecutive repeating chars
    for i in range (len(pwd)):
        cur_cnt = 1
        for j in range (i+1, len(pwd)):
            if (pwd[i] != str[j]):
                break
            cur_cnt += 1
        if cur_cnt > 2:
            return "Invalid password, password must not contain more than 2 consecutive repeating characters", 400

@app.route("/signUp", methods=['POST'])
def sign_up():
    # TODO - sanitize signup paramaters
    #   - check for valid email and password
    #   - Exception behavior
    if request.authorization is None or request.authorization.username \
       is None or request.authorization.password is None:
        return "Authorization header not supplied", 400

    # check if valid email
    email = request.authorization.username
    checkemail(email)

    # check if valid password
    pwd = request.authorization.password
    checkpwd(pwd)

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
    email = request.json["user"]
    checkemail(email)

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
