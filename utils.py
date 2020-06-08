from flask import request, make_response
from google.auth.transport import requests
from google.oauth2 import id_token
from secrets import client_id
from constants import crates, crate_attributes, json_mimetype, vinyl


def crate_information(crate_info_json):
    crate_result = {}
    for attribute in crate_attributes:
        if attribute not in crate_info_json:
            return False

        if attribute == "capacity":
            if not type(crate_info_json[attribute]) == int or crate_info_json[attribute] <= 0:
                return False
        else:
            if not type(crate_info_json[attribute]) == str or len(crate_info_json[attribute]) < 1:
                return False

        crate_result[attribute] = crate_info_json[attribute]

    crate_result["vinyl"] = []
    return crate_result


def crate_self(crate_id, path):
    return path + crates + "/" + str(crate_id)


def create_return(data, status):
    res = make_response(data)
    res.mimetype = json_mimetype
    res.status_code = int(status)
    return res


def verify(headers):
    try:
        if "Authorization" not in headers:
            return -1
        bearer = headers["Authorization"]
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


def vinyl_self(vinyl_id, path):
    return path + vinyl + "/" + str(vinyl_id)