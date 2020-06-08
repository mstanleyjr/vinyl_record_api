import json


def status_400():
    return json.dumps({"Error": "The request object is missing at least one valid, required attributes"})


def status_401():
    return json.dumps({"Error": "Invalid or missing authorization token"})


def status_405():
    return json.dumps({"Error": "Method is not allowed for this endpoint"})


def status_406():
    return json.dumps({"Error": "Content-type requested is not supported by this endpoint"})
