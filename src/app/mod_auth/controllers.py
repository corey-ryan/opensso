import time, os, uuid, jwt
from os.path import dirname, exists, join, sep
from flask import (Flask, request, redirect, make_response,  Blueprint, flash, g, url_for, jsonify, current_app)
#from flask_dynamodb_sessions import Session
from flask_cors import CORS, cross_origin
import urllib.parse
from app.common.saml2.auth import OneLogin_Saml2_Auth
from app.common.saml2.utils import OneLogin_Saml2_Utils

from functools import wraps

from flask import current_app as app
from app.common import controllers as common

mod_auth = Blueprint('auth', __name__, url_prefix='/auth', static_folder='static')

def init_saml_auth(req, target_app, role):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'], target_app=target_app, role=role)
    return auth

def prepare_flask_request(request):
    https = None
    if 'X-Forwarded-Proto' in request.headers:
        https == 'on' if request.headers['X-Forwarded-Proto'] == 'https' else 'off'
    else:
        https = 'on' if request.scheme == 'https' else 'off'
    return {
        'https': https,
        'http_host': request.host,
        'server_port': None,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def clear_sessions(session_id):
    app.slack_map_interface.delete(session_id)
    return True

def encode_auth_token(payload):
    try:
        cert_path = app.config['SAML_PATH'] + sep + 'certs' + sep + 'privatejwt.pem'
        if exists(cert_path):
            with open(cert_path) as f:
                private_key = f.read()
        encoded = jwt.encode(payload, private_key, algorithm='RS256')
        return encoded
    except Exception as e:
        return e

def decode_auth_token(auth_token, audience):
    try:
        cert_path = app.config['SAML_PATH'] + sep + 'certs' + sep + 'publicjwt.pem'
        if exists(cert_path):
            with open(cert_path) as f:
                public_key = f.read()
        payload = jwt.decode(auth_token, public_key, audience=audience, algorithm='RS256')
        return payload
    except jwt.ExpiredSignatureError:
        return { 'errors' : 'Signature expired. Please log in again.' }
    except jwt.InvalidTokenError:
        return { 'errors': 'Invalid token. Please log in again.' }

def slack_session_valid(user):
    if 'RUN_LOCAL' in os.environ:
        return True
    else:
        print("Checking Slack Session")
        mapping_info = app.slack_map_interface.open(session, user)
        print(mapping_info)
        if mapping_info is not None:
            epoch_time = int(time.time())
            session_expire = int(mapping_info['ttl'])
            if epoch_time < session_expire:
              return True
    return False

def session_valid(target_app, role):
    if 'RUN_LOCAL' in os.environ:
        return True
    else:
        decoded = None
        print(request.headers)
        if 'Authorization' in request.headers and "Bearer" in request.headers['Authorization']:
            audience = f"{target_app}:{role}"
            decoded = decode_auth_token(request.headers['Authorization'].split("Bearer ")[1], audience)
        
    return decoded

def slack_login_required(protected_function):
  @wraps(protected_function)
  def wrapper(*args, **kwargs):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    if slack_session_valid(request.form['user_id']):
      return protected_function(*args, **kwargs)
    else:
      return f"You are: {request.form['user_name']} ({request.form['user_id']}) Authenticated: False \nTo map your session please visit: https://app.tldr.mgmt.cardsavr.io/#/session/slackmap/{request.form['user_id']}"
  return wrapper

def login_required(protected_function):
  @wraps(protected_function)
  def wrapper(target_app=None, role=None, *args, **kwargs):
    req = prepare_flask_request(request)
    session_check = session_valid(target_app, role)
    if session_check:
      return protected_function(target_app, role, session_check, *args, **kwargs)
    else:
      return redirect(auth.login())
  return wrapper

@mod_auth.route('/session/<target_app>/<role>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
@login_required
def auth_session(target_app=None, role=None, payload=None):
    return jsonify(payload)

@mod_auth.route('/slack/session/<target_app>/<role>/<user_id>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def auth_slack_session(target_app=None, role=None, user_id=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    check = session_valid(target_app, role)
    if 'data' in check:
        app.slack_map_interface.save(check, user_id)
        return jsonify(check)
    else:
        return jsonify({"mapped": False, "errors": [ "Invalid Token" ]})  

@mod_auth.route('/sso/<target_app>/<role>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True, allow_headers="*", )
def auth_login(target_app=None, role=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    request_data = request.get_json()
    if 'RelayState' in request.get_json():
        url = request_data['RelayState']
    else:
        url = f"https://app.{target_app}.mgmt.cardsavr.io/"
    return jsonify({'ssourl': auth.login(return_to=url)}), 200

@mod_auth.route('/slo/<target_app>/<role>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def auth_slo(target_app=None, role=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)

    audience = f"{target_app}:{role}" 
    decoded = decode_auth_token(req['post_data']['token'], audience)

    if 'samlSessionIndex' in decoded['data']['samlSessionIndex']:
        session_index = decoded['data']['samlSessionIndex']
   
    clear_sessions(decoded['data']['samlSessionIndex'])
   
    if return_to is not None:
        return redirect(return_to)

    return jsonify({"ssourl": auth.logout(name_id=name_id, session_index=session_index, return_to=f"https://{request.host}/auth/sls") }), 200

@mod_auth.route('/acs/<target_app>/<role>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def auth_acs(target_app=None, role=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    auth.process_response()
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()
    # if len(errors) == 0:
    #     token = encode_auth_token({ 
    #         'exp': auth.get_session_expiration(),
    #         'aud': f"{target_app}:{role}",
    #         'data' : {
    #             'samlSessionIndex': auth.get_session_index(), 
    #             'userdata': auth.get_attributes(), 
    #         }
    #     })
    #     form_data = {'token': token}
    #     self_url = OneLogin_Saml2_Utils.get_self_url(req)
    #     if 'RelayState' in request.form and self_url != request.form['RelayState']:
    #         redirect_to = f"{auth.redirect_to(request.form['RelayState'])}?{urllib.parse.urlencode(form_data)}"
    #     else:
    #         redirect_to = auth.redirect_to(f"https://{target_app}.mgmt.cardsavr.io?") + urllib.parse.urlencode(form_data)
    #     return redirect(redirect_to)
    # else:
    #     form_data = {'logged_in': False, 'errors': errors}
    #     return redirect(redirect_to)
    if len(errors) == 0:
        token = encode_auth_token({ 
            'exp': auth.get_session_expiration(),
            'aud': f"{target_app}:{role}",
            'data' : {
                'samlSessionIndex': auth.get_session_index(), 
                'userdata': auth.get_attributes(), 
            }
        })
        form_data = {'token': token}
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            redirect_to = f"{auth.redirect_to(request.form['RelayState'])}"
        else:
            redirect_to = auth.redirect_to(f"https://{target_app}.mgmt.cardsavr.io?")
        response = make_response(redirect(redirect_to))
        domain = f"{app.config['SESSION_COOKIE_DOMAIN']}"
        response.set_cookie('token', token, domain=domain)
    else:
        response = make_response(redirect(redirect_to))
    return response

@mod_auth.route('/sls/<target_app>/<role>', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def auth_sls(target_app=None, role=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    dscb = lambda: session.clear()
    url = auth.process_slo(delete_session_cb=dscb)
    errors = auth.get_errors()
    if len(errors) == 0:
        if url is not None:
            return redirect(url)
        else:
            success_slo = True
    return "Logged Out"

@mod_auth.route('/metadata/<target_app>/<role>')
@cross_origin(supports_credentials=True)
def auth_metadata(target_app=None, role=None):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req, target_app, role)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(errors.join(', '), 500)
    return resp
