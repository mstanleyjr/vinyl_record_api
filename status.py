import json


def status_400():
    return json.dumps({"Error": "The request object is missing at least one valid, required attributes"})


def status_400_store():
    return json.dumps({"Error": "The vinyl already has a crate or crate is full"})


def status_400_withdraw():
    return json.dumps({"Error": "This vinyl is not in this crate"})


def status_401():
    return json.dumps({"Error": "Invalid or missing authorization token"})


def status_403():
    return json.dumps({"Error": "Action is forbidden by anyone other than owner of crate"})


def status_404(object):
    return json.dumps({"Error": f'No {object} with this {object}_id exists'})


def status_404_store():
    return json.dumps({"Error": "The specified crate and/or vinyl doesn’t exist"})


def status_405():
    return json.dumps({"Error": "Method is not allowed for this endpoint"})


def status_406():
    return json.dumps({"Error": "Content-type requested is not supported by this endpoint"})
