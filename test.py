#!/usr/bin/env python3

import boto3
import dotenv
from os import environ

dotenv.load_dotenv()
client = boto3.client("dynamodb", region_name=environ["AWS_REGION"])

def test():
    try:
        response = client.get_item(TableName='userData', Key={ 'UUID': { 'S' : "jamal"} })

    except client.exceptions.ResourceNotFoundException:
        return "no such record"

    if "Item" not in response.keys():
        return "UUID not present"

    return response["Item"]

print(test())
