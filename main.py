import json
from flask import Flask, render_template, request, make_response
from google.auth.transport import requests
from google.cloud import datastore
from google.oauth2 import id_token
from requests_oauthlib import OAuth2Session
from secrets import client_id, client_secret
from constants import redirect_uri, scope, google_auth_endpoint, users, json_mimetype, all_mimetype
from status import status_405, status_406
from utils import create_return, verify

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
    return create_return(json.dumps({"users": results}), 200)


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
