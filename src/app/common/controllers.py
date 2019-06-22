import time, urllib, json, datetime
from flask import current_app as app

class SlackMessage(object):

  def __init__(self, url, oauth):
    self.url = url
    self.options = {}
    self.oauth = oauth

  def send(self, options=None):
    if options is not None:
      self.options = options
    headers = {'content-type': 'application/json', "Authorization": f"Bearer {self.oauth}"}
    timestamp = int(round(time.time()))
    req = urllib.request.Request(self.url, data=json.dumps(self.options).encode("utf8"), headers=headers, method="POST")
    resp = urllib.request.urlopen(req)
    return resp


class AWSTime(object):
  def __init__(self, time):
    self.time = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")

  def normal(self):
    return self.time.strftime('%H:%M:%S - %m/%d/%Y')