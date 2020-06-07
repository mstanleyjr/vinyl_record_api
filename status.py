import json


def status_405():
    return json.dumps({"Error": "Method is not allowed for this endpoint"})


def status_406():
    return json.dumps({"Error": "Content-type requested is not supported by this endpoint"})
