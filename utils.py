from flask import request, make_response
from google.auth.transport import requests
from google.oauth2 import id_token
from secrets import client_id
from constants import json_mimetype


def create_return(data, status):
    res = make_response(data)
    res.mimetype = json_mimetype
    res.status_code = int(status)
    return res


def verify(bearer):
    try:
        space_index = bearer.index(" ")
        prior = bearer[:space_index]
        if prior != "Bearer":
            raise ValueError
        jwt = bearer[space_index + 1:]
        req = requests.Request()
        id_info = id_token.verify_oauth2_token(
            str(jwt), req, client_id)
        return id_info["sub"]
    except ValueError:
        return -1
