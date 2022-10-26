#!/usr/bin/env python3

"""
Current - testing JWT validation.
"""
import jwt
from json import loads
from os import environ
from datetime import datetime
from flask import (Flask, request)
import boto3
import dotenv

dotenv.load_dotenv()
jwk =  loads(open("jwks.json", "r").read())
client = boto3.client("dynamodb", region_name=environ["AWS_REGION"])

# question - use this file or the other file for jwt validation

def jwtDecode(inp):
    try:
        header = jwt.get_unverified_header(inp)
    except:
        return None
    for i in jwk["keys"]:
        if header["kid"] == i["kid"]:
            pubkey = jwt.algorithms.RSAAlgorithm.from_jwk(i)
            try:
                out = jwt.decode(inp, pubkey, algorithms=["RS256"],
                                 options={"require": ["exp", "iss", "client_id"],
                                          "verify_exp": datetime.now()},
                                 iss=f"https://cognito-idp.{environ['AWS_REGION']}.amazonaws.com/{environ['COGNITO_POOL_ID']}")
                return out if out["client_id"] in [environ["COGNITO_CLIENT_ID"]] and \
                    out["token_use"]=="access" else None
            except:
                return None
    return None

app = Flask(__name__)

@app.route("/userData", methods=["GET"])
def userData():
    if "Authorization" not in request.headers or "JWT" not in request.headers["Authorization"]:
        return "No bearer token supplied", 401
    token = request.headers["Authorization"].split("JWT ", 1)[1].strip()
    out = jwtDecode(token)
    if not out:
        return "Invalid JWT", 401
    user = out["sub"]
    try:
        response = client.get_item(TableName='userData', Key={ 'UUID': { 'S' : user} }, ProjectionExpression="records")
    except client.exceptions.ResourceNotFoundException:
        return "no such record", 400
    except:
        return "internal error", 400
    if "Item" not in response.keys():
        return "UUID not present",400
    return response["Item"]

@app.route("/putData", methods=["POST"])
def putLog():
    if not request.json or "deviceID" not in request.json:
        return "No deviceID specified in JSON load", 400
    if "Authorization" not in request.headers or "JWT" not in request.headers["Authorization"]:
        return "No bearer token supplied", 401
    token = request.headers["Authorization"].split("JWT ", 1)[1].strip()
    out = jwtDecode(token)
    if not out:
        return "Invalid JWT", 401
    user = out["sub"]
    try:
        response = client.get_item(TableName='userData', Key={ 'UUID': { 'S' : user} }, ProjectionExpression="records")
    except:
        return "internal error", 400
    if "Item" not in response.keys():
        return "UUID not present",400

    dID = request.json["deviceID"]
    data = response["Item"]["records"]["L"]
    for i in data:
        i = i["M"]
        if dID.strip() == i["deviceID"]["S"].strip():
            record = i["record"]["S"]
            try:
                client.update_item(
                    Key={ 'record-id': { 'S' : record} },
                    TableName="recordLogs",
                    ExpressionAttributeNames={
                        "#L" : "logs",
                        "#TS" : str(int(round(datetime.now().timestamp())))
                    },
                    ExpressionAttributeValues={
                        ':l': {
                            'M': {
                                'lightR': {
                                    'N': str(43.2)
                                },
                                'temp': {
                                    'N': str(73.4)
                                }
                            }
                        }
                    }, UpdateExpression="SET #L.#TS = :l"
                )
                return "Success"
            except:
                return "Update failed", 400

    return "Device ID not found in user records", 405


app.run("0.0.0.0", 5000, load_dotenv=True)
