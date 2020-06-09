import json
from flask import Flask, render_template, request, make_response
from google.auth.transport import requests
from google.cloud import datastore
from google.oauth2 import id_token
from requests_oauthlib import OAuth2Session
from secrets import client_id, client_secret
from constants import crates, redirect_uri, scope, google_auth_endpoint, users, json_mimetype, all_mimetype, \
    paginate_limit, vinyl
from status import status_400, status_400_store, status_400_withdraw, status_401, status_403, status_404, \
    status_404_store, status_405, \
    status_406
from utils import crate_information, crate_information_indiv, object_self, create_return, verify, vinyl_information, \
    vinyl_information_indiv

# This disables the requirement to use HTTPS so that you can test locally.
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
datastore_client = datastore.Client()

oauth = OAuth2Session(client_id, redirect_uri=redirect_uri,
                      scope=scope)


@app.before_request
def request_checks():
    mimetype_dict = dict(request.accept_mimetypes)
    if json_mimetype not in mimetype_dict and all_mimetype not in mimetype_dict:
        return create_return(status_406(), 406)


@app.route('/')
def root():
    authorization_url, state = oauth.authorization_url(
        google_auth_endpoint,
        access_type="offline", prompt="select_account")
    return render_template("index.html", auth_url=authorization_url)


@app.route('/oauth')
def oauthroute():
    token = oauth.fetch_token(
        'https://accounts.google.com/o/oauth2/token',
        authorization_response=request.url,
        client_secret=client_secret)
    req = requests.Request()

    id_info = id_token.verify_oauth2_token(
        token['id_token'], req, client_id)
    # Check that user is not already in db
    query = datastore_client.query(kind=users)
    query.add_filter("sub", "=", id_info["sub"])
    result = list(query.fetch())
    if len(result) == 0:
        # Save to User DB - Email, and sub as id.
        new_user_attributes = {"email": id_info["email"], "sub": id_info["sub"]}
        new_user = datastore.Entity(key=datastore_client.key(users))
        new_user.update(new_user_attributes)
        datastore_client.put(new_user)

    return render_template("user_info.html", email_address=id_info["email"], jwt=token["id_token"], id=id_info["sub"])


@app.route('/users', methods=["GET"])
def get_users():
    query = datastore_client.query(kind=users)
    results = list(query.fetch())
    for result in results:
        result["id"] = result.pop("sub")
    return create_return(json.dumps({"users": results, "collection_size": len(results)}), 200)


@app.route('/crates', methods=["POST", "GET"])
def post_crates():
    if request.method == "POST":
        # Verify user
        verified = verify(request.headers)
        if verified == -1:
            return create_return(status_401(), 401)

        if not request.data:
            return create_return(status_400(), 400)

        crate_info = crate_information(request.get_json())
        if not crate_info:
            return create_return(status_400(), 400)

        crate_info["owner"] = verified
        crate_info["vinyl"] = []
        new_crate = datastore.Entity(key=datastore_client.key(crates))
        new_crate.update(crate_info)
        datastore_client.put(new_crate)
        crate_info["id"] = str(new_crate.key.id)
        crate_info["self"] = object_self(new_crate.key.id, crates, request.url_root)

        return create_return(json.dumps(crate_info), 201)

    if request.method == "GET":
        #         Verify user but don't return error
        verified = verify(request.headers)
        #         Get crates belonging to this user
        query = datastore_client.query(kind=crates)
        query.add_filter("owner", "=", str(verified))
        collection_size = len(list(query.fetch()))
        q_offset = int(request.args.get('offset', 0))
        crate_iterator = query.fetch(limit=paginate_limit, offset=q_offset)
        pages = crate_iterator.pages
        results = list(next(pages))
        for result in results:
            result["id"] = result.key.id
            result["self"] = object_self(result.key.id, crates, request.url_root)

            for vinyl_record in result["vinyl"]:
                vinyl_record["self"] = object_self(vinyl_record["id"], vinyl, request.url_root)
                vinyl_key = datastore_client.key(vinyl, int(vinyl_record["id"]))
                vinyl_object = datastore_client.get(vinyl_key)
                vinyl_record["title"] = vinyl_object["title"]

        return_info = {"crates": results, "collection_size": collection_size}

        if crate_iterator.next_page_token:
            next_offset = q_offset + paginate_limit
            next_url = request.base_url + "?offset=" + str(next_offset)
            return_info["next"] = next_url

        return create_return(json.dumps(return_info), 200)


@app.route('/crates/<crate_id>', methods=["GET", "DELETE", "PATCH", "PUT"])
def get_delete_patch_put_crate_crateid(crate_id):
    # Verify user
    verified = verify(request.headers)
    if verified == -1:
        return create_return(status_401(), 401)

    #       Get crate
    crate_key = datastore_client.key(crates, int(crate_id))
    crate = datastore_client.get(key=crate_key)

    if crate is None:
        return create_return(status_404("crate"), 404)

    #       Verify ownership
    if crate["owner"] != str(verified):
        return create_return(status_403(), 403)

    if request.method == "DELETE":
        # Delete crate

        # Remove Vinyl in future update
        # vinyl = crate["vinyl"]

        for record in crate["vinyl"]:
            #     Get vinyl and remove the crate
            vinyl_key = datastore_client.key(vinyl, int(record["id"]))
            vinyl_record = datastore_client.get(key=vinyl_key)
            vinyl_record["crate"] = None
            vinyl_record.update(vinyl_record)
            datastore_client.put(vinyl_record)

        datastore_client.delete(crate_key)

        return create_return("", 204)

    if request.method == "PATCH":
        if not request.data:
            return create_return(status_400(), 400)
        crate_attributes = crate_information_indiv(request.get_json())

        if not crate_attributes:
            return create_return(status_400(), 400)

        crate.update(crate_attributes)
        datastore_client.put(crate)

    if request.method == "PUT":
        if not request.data:
            return create_return(status_400(), 400)

        crate_attributes = crate_information(request.get_json())

        if not crate_attributes:
            return create_return(status_400(), 400)

        crate.update(crate_attributes)
        datastore_client.put(crate)
        crate["id"] = crate.key.id
        crate["self"] = object_self(crate.key.id, crates, request.url_root)
        for vinyl_record in crate["vinyl"]:
            vinyl_record["self"] = object_self(vinyl_record["id"], vinyl, request.url_root)
            vinyl_key = datastore_client.key(vinyl, int(vinyl_record["id"]))
            vinyl_object = datastore_client.get(vinyl_key)
            vinyl_record["title"] = vinyl_object["title"]
        #     Return 303
        res = make_response(crate)
        res.status_code = 303
        res.headers.set("Location", crate["self"])
        return res

    # Fall through for requests that return 200 response (GET and PATCH)
    crate["id"] = crate.key.id
    crate["self"] = object_self(crate.key.id, crates, request.url_root)
    for vinyl_record in crate["vinyl"]:
        vinyl_record["self"] = object_self(vinyl_record["id"], vinyl, request.url_root)
        vinyl_key = datastore_client.key(vinyl, int(vinyl_record["id"]))
        vinyl_object = datastore_client.get(vinyl_key)
        vinyl_record["title"] = vinyl_object["title"]

    return create_return(json.dumps(crate), 200)


@app.route('/vinyl', methods=["POST", "GET"])
def post_get_vinyl():
    if request.method == "POST":
        if not request.data:
            return create_return(status_400(), 400)
        vinyl_info = vinyl_information(request.get_json())

        if not vinyl_info:
            return create_return(status_400(), 400)

        vinyl_info["crate"] = None
        new_vinyl = datastore.Entity(key=datastore_client.key(vinyl))
        new_vinyl.update(vinyl_info)
        datastore_client.put(new_vinyl)
        vinyl_info["id"] = str(new_vinyl.key.id)
        vinyl_info["self"] = object_self(new_vinyl.key.id, vinyl, request.url_root)

        return create_return(json.dumps(vinyl_info), 201)

    if request.method == "GET":
        query = datastore_client.query(kind=vinyl)
        collection_size = len(list(query.fetch()))
        q_offset = int(request.args.get('offset', 0))
        vinyl_iterator = query.fetch(limit=paginate_limit, offset=q_offset)
        pages = vinyl_iterator.pages
        results = list(next(pages))
        for result in results:
            result["id"] = str(result.key.id)
            result["self"] = object_self(result.key.id, crates, request.url_root)

            if result["crate"] is not None:
                crate_key = datastore_client.key(crates, int(result["crate"]["id"]))
                crate = datastore_client.get(crate_key)
                crate["id"] = crate.key.id
                crate["self"] = object_self(crate.key.id, crates, request.url_root)
                crate.pop("vinyl", None)
                result["crate"] = crate

        return_info = {"vinyl": results, "collection_size": collection_size}

        if vinyl_iterator.next_page_token:
            next_offset = q_offset + paginate_limit
            next_url = request.base_url + "?offset=" + str(next_offset)
            return_info["next"] = next_url

        return create_return(json.dumps(return_info), 200)


@app.route('/vinyl/<vinyl_id>', methods=["GET", "PATCH", "PUT", "DELETE"])
def get_patch_put_delete_vinyl_vinylid(vinyl_id):
    # Get the vinyl
    vinyl_key = datastore_client.key(vinyl, int(vinyl_id))
    vinyl_record = datastore_client.get(key=vinyl_key)

    if vinyl_record is None:
        return create_return(status_404(vinyl), 404)

    crate = None
    # If record in crate get crate information
    if vinyl_record["crate"] is not None:
        crate_key = datastore_client.key(crates, int(vinyl_record["crate"]["id"]))
        crate = datastore_client.get(crate_key)
        crate["self"] = object_self(crate.key.id, crates, request.url_root)
        crate["id"] = str(crate.key.id)
        # vinyl_record["crate"] = crate

    if request.method == "PATCH":
        # Verify the user if the vinyl is in a crate
        if vinyl_record["crate"] is not None:
            verified = verify(request.headers)
            if verified == -1:
                return create_return(status_401(), 401)

            if crate["owner"] != str(verified):
                return create_return(status_403(), 403)

        if not request.data:
            return create_return(status_400(), 400)
        vinyl_attributes = vinyl_information_indiv(request.get_json())

        if not vinyl_attributes:
            return create_return(status_400(), 400)

        vinyl_record.update(vinyl_attributes)
        datastore_client.put(vinyl_record)

    if request.method == "PUT":
        if vinyl_record["crate"] is not None:
            verified = verify(request.headers)
            if verified == -1:
                return create_return(status_401(), 401)

            if crate["owner"] != str(verified):
                return create_return(status_403(), 403)

        if not request.data:
            return create_return(status_400(), 400)

        vinyl_attributes = vinyl_information(request.get_json())

        if not vinyl_attributes:
            return create_return(status_400(), 400)

        vinyl_record.update(vinyl_attributes)
        datastore_client.put(vinyl_record)
        vinyl_record["id"] = vinyl_record.key.id
        vinyl_record["self"] = object_self(vinyl_record.key.id, vinyl, request.url_root)
        if crate is not None:
            crate.pop("vinyl", None)
        vinyl_record["crate"] = crate

        # For records in vinyl
        #     Return 303
        res = make_response(vinyl_record)
        res.status_code = 303
        res.headers.set("Location", vinyl_record["self"])
        return res

    if request.method == "DELETE":
        # Delete vinyl
        if vinyl_record["crate"] is not None:
            verified = verify(request.headers)
            if verified == -1:
                return create_return(status_401(), 401)

            if crate["owner"] != str(verified):
                return create_return(status_403(), 403)

            for i in range(len(crate["vinyl"])):
                if crate["vinyl"][i]["id"] == str(vinyl_id):
                    crate["vinyl"].pop(i)
                    crate.update(crate)
                    datastore_client.put(crate)
                    break

        datastore_client.delete(vinyl_key)

        return create_return("", 204)

    # Fall through for GET and PATCH
    vinyl_record["id"] = str(vinyl_record.key.id)
    vinyl_record["self"] = object_self(vinyl_record.key.id, vinyl, request.url_root)
    if crate is not None:
        crate.pop("vinyl", None)
    vinyl_record["crate"] = crate

    return create_return(json.dumps(vinyl_record), 200)


@app.route("/crates/<crate_id>/vinyl/<vinyl_id>/store", methods=["PUT"])
def store_vinyl(crate_id, vinyl_id):
    # Verify user
    verified = verify(request.headers)
    if verified == -1:
        return create_return(status_401(), 401)

    # Get crate and vinyl
    # Get the vinyl
    vinyl_key = datastore_client.key(vinyl, int(vinyl_id))
    vinyl_record = datastore_client.get(key=vinyl_key)

    crate_key = datastore_client.key(crates, int(crate_id))
    crate = datastore_client.get(key=crate_key)

    if crate is None or vinyl_record is None:
        return create_return(status_404_store(), 404)
    #     Verify user is owner of crate
    if crate["owner"] != str(verified):
        return create_return(status_403(), 403)

    #     Verify vinyl does not have crate
    if vinyl_record["crate"] is not None:
        return create_return(status_400_store(), 400)

    #     Verify capacity constraints
    if len(crate["vinyl"]) + 1 > crate["capacity"]:
        return create_return(status_400_store(), 400)

    #     Add vinyl to crate
    crate["vinyl"].append({"id": str(vinyl_record.key.id)})
    crate.update(crate)
    datastore_client.put(crate)

    #     Add crate to vinyl
    vinyl_record["crate"] = {"id": str(crate.key.id)}
    vinyl_record.update(vinyl_record)
    datastore_client.put(vinyl_record)

    #     Return 204
    return create_return("", 204)


@app.route("/crates/<crate_id>/vinyl/<vinyl_id>/withdraw", methods=["DELETE"])
def withdraw_vinyl(crate_id, vinyl_id):
    # Verify user
    verified = verify(request.headers)
    if verified == -1:
        return create_return(status_401(), 401)

    # Get crate and vinyl
    # Get the vinyl
    vinyl_key = datastore_client.key(vinyl, int(vinyl_id))
    vinyl_record = datastore_client.get(key=vinyl_key)

    crate_key = datastore_client.key(crates, int(crate_id))
    crate = datastore_client.get(key=crate_key)

    if crate is None or vinyl_record is None:
        return create_return(status_404_store(), 404)
    #     Verify user is owner of crate
    if crate["owner"] != str(verified):
        return create_return(status_403(), 403)

    record_found = False
    #    Remove relationship
    for i in range(len(crate["vinyl"])):
        if crate["vinyl"][i]["id"] == str(vinyl_id):
            crate["vinyl"].pop(i)
            crate.update(crate)
            datastore_client.put(crate)
            record_found = True
            break

    if not record_found:
        return create_return(status_400_withdraw(), 400)

    vinyl_record["crate"] = None
    vinyl_record.update(vinyl_record)
    datastore_client.put(vinyl_record)

    return create_return("", 204)


@app.errorhandler(405)
def method_not_allowed(e):
    return create_return(status_405(), 405)


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8081, debug=True)
