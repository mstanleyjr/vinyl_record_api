from flask import request, make_response
from google.auth.transport import requests
from google.oauth2 import id_token
from google.cloud import datastore
from secrets import client_id
from constants import crates, crate_attributes, json_mimetype, vinyl, vinyl_attributes


def crate_information(crate_info_json):
    crate_result = {}
    for attribute in crate_attributes:
        if attribute not in crate_info_json:
            return False

        if not crate_attr_check(crate_info_json[attribute], attribute):
            return False
        crate_result[attribute] = crate_info_json[attribute]

    return crate_result


def crate_information_indiv(crate_info_json):
    crate_result = {}
    for attribute in crate_info_json:
        if attribute in crate_attributes:
            if not crate_attr_check(crate_info_json[attribute], attribute):
                return False

            crate_result[attribute] = crate_info_json[attribute]

    return crate_result


def crate_attr_check(attribute, attribute_name):
    if attribute_name == "capacity":
        if not type(attribute) == int or attribute <= 0:
            return False
    else:
        if not type(attribute) == str or len(attribute) < 1:
            return False

    return True


def object_self(object_id, constant_name, path):
    return path + constant_name + "/" + str(object_id)


def create_return(data, status):
    res = make_response(data)
    res.mimetype = json_mimetype
    res.status_code = int(status)
    return res


def new_object(object_info, kind_constant, ds_client, path):
    new_object = datastore.Entity(key=ds_client.key(kind_constant))
    new_object.update(object_info)
    ds_client.put(new_object)
    object_info["id"] = str(new_object.key.id)
    object_info["self"] = object_self(new_object.key.id, kind_constant, path)
    return object_info


def vinyl_in_crate(crate, ds_client, path):
    crate["id"] = crate.key.id
    crate["self"] = object_self(crate.key.id, crates, path)

    for vinyl_record in crate["vinyl"]:
        vinyl_record["self"] = object_self(vinyl_record["id"], vinyl, path)
        vinyl_key = ds_client.key(vinyl, int(vinyl_record["id"]))
        vinyl_object = ds_client.get(vinyl_key)
        vinyl_record["title"] = vinyl_object["title"]


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


def vinyl_information(vinyl_info_json):
    vinyl_result = {}
    for attribute in vinyl_attributes:
        if attribute not in vinyl_info_json:
            return False

        if not vinyl_attr_check(vinyl_info_json[attribute], attribute):
            return False

        vinyl_result[attribute] = vinyl_info_json[attribute]

    return vinyl_result


def vinyl_information_indiv(vinyl_info_json):
    vinyl_result = {}
    for attribute in vinyl_info_json:
        if attribute in vinyl_attributes:
            if not vinyl_attr_check(vinyl_info_json[attribute], attribute):
                return False

            vinyl_result[attribute] = vinyl_info_json[attribute]

    return vinyl_result


def vinyl_attr_check(attribute, attribute_name):
    if attribute_name == "release_year":
        if not type(attribute) == int or attribute <= 0:
            return False
    else:
        if not type(attribute) == str or len(attribute) < 1:
            return False

    return True
