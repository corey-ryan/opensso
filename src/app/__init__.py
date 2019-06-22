# Import flask and template operators
from flask import Flask, render_template, request, redirect
from flask.logging import default_handler
from flask_cors import CORS, cross_origin
import boto3, os, json, urllib.request, time, datetime, logging, uuid
from app.common.ddbsession import SlackMap


class HealthCheckFilter(logging.Filter):
  def filter(self, record):
    return "healthcheck" in record.getMessage()

root = logging.getLogger()
root.addFilter(HealthCheckFilter())
#root.addHandler(default_handler)
#default_handler.addFilter(HealthCheckFilter()) 

# Define the WSGI application object
app = Flask(__name__)

# Configurations
app.config.from_object('config')

###
### HealthCheck
###
@app.route("/healthcheck", methods=['GET'])
def healthcheck():
  return "I am putting myself to the fullest possible use, which is all I think that any conscious entity can ever hope to do."

CORS(app, support_credentials=True, resources={r"/*": {"origins": [ "http://localhost*" ]}})
SlackMap(app)

# Sample HTTP error handling
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

from app.mod_auth.controllers import mod_auth as auth

# Register blueprint(s)
app.register_blueprint(auth)
