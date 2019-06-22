# -*- coding: utf-8 -*-

import sys
import time
from datetime import datetime
from uuid import uuid4
from flask.sessions import SessionInterface
from flask.sessions import SessionMixin
from flask import request
from werkzeug.datastructures import CallbackDict
import json
import boto3
from urllib.parse import urlparse
from boto3.dynamodb.conditions import Key
from operator import itemgetter
PV3 = sys.version_info[0] == 3

import pickle
import codecs


class SlackMap(object):

    def __init__(self, app=None, **kw):
        self.app = app
        self.permanent = kw.get('permanent', True)
        
        if self.app is not None:
            self.init(self.app)

    def init(self, app):
        conf = app.config.copy()

        conf.setdefault("SLACK_MAPPING_TABLE", "tldr_slack_map_table")
        conf.setdefault("SLACK_MAPPING_REGION", "us-west-2")
        conf.setdefault("SLACK_MAPPING_ENDPOINT", None)
        conf.setdefault("SLACK_MAPPING_TTL_SECONDS", (7200))

        kw = {
            'table': conf['SLACK_MAPPING_TABLE'],
            'endpoint': conf['SLACK_MAPPING_ENDPOINT'],
            'region': conf['SLACK_MAPPING_REGION'],
            'ttl': conf['SLACK_MAPPING_TTL_SECONDS'],
            'permanent': self.permanent,
        }

        interface = SlackMapInterface(**kw)

        app.slack_map_interface = interface


class SlackMapInterface():
    """
    """
    _boto_client = None
    _boto_table = None

    def __init__(self, **kw):
        self.table = kw.get('table', 'flask_sessions')
        self.permanent = kw.get('permanent', True)
        self.endpoint = kw.get('endpoint', None)
        self.region = kw.get('region', None)
        self.ttl = kw.get('ttl', None)

    def open(self, session, user):
        """
        """
        data = None
        data = self.get_by_id(user)

        return data

    def pickle_data(self, data):
        """Pickle the session object and base64 encode it
            for storage as a dynamo string
        """
        pickled = pickle.dumps(data)

        canned = codecs.encode(pickled, 'base64').decode()

        return canned

    def hydrate_data(self, data):
        """Base64 decode string back to bytes and unpickle
        """
        uncanned = codecs.decode(data.encode(), 'base64')

        pickled = pickle.loads(uncanned)

        return pickled

    # def get(self, saml_session_index):
    #     """
    #     """
    #     try:
    #         res = self.boto_client().get_item(TableName=self.table,IndexName='slack_id-index',
    #                     Key={'id':{'S': saml_session_index}})
    #         if res.get('Item').get('data'):
    #             data = res.get('Item').get('data')
    #             return data.get('S', '{}')
    #     except Exception as e:
    #         print("DYNAMO SESSION GET ITEM ERR: ", str(e))

    #     return None

    def get_by_id(self, slack_id):
        """
        """
        try:
            res = self.boto_table().query(IndexName='slack_id-index',KeyConditionExpression=Key('slack_id').eq(slack_id))
    
            if res.get('Items'):
                data = res.get('Items')
                if len(data) > 1:
                    sorted_list = sorted(data, key=itemgetter('ttl'), reverse=True)
                    data = sorted_list[0]
                return data[0]
        except Exception as e:
            print("DYNAMO SESSION GET ITEM ERR: ", str(e))

        return None

    def save(self, session, data):
        try:
           
            self.ttl = session['exp']

            fields = {
                'modified': {'S': str(datetime.utcnow())},
                'ttl': {'N': str(self.ttl)}
            }

            attr_names = {}
            attr_vals = {}
            ud_exp = []
            for k, v in fields.items():
                attr = "#attr_{}".format(k)
                token = ":{}".format(k)
                ud_exp.append("{} = {}".format(attr, token))
                attr_vals[token] = v
                attr_names[attr] = k
            self.boto_client().update_item(TableName=self.table,
                        Key={'id':{'S':session['data']['samlSessionIndex']}, 'slack_id':{'S':data}},
                        ExpressionAttributeNames=attr_names,
                        ExpressionAttributeValues=attr_vals,
                        UpdateExpression="SET {}".format(", ".join(ud_exp)),
                        ReturnValues='NONE')
        except Exception as e:
            print("DYNAMO SESSION SAVE ERR: ", str(e))

    def delete(self, session):
        try:
            self.boto_client().delete_item(TableName=self.table,
                        Key={'id':{'S':session}})
        except Exception as e:
            print("DYNAMO SESSION DELETE ERR: ", str(e))

    def boto_table(self):

        if self._boto_table is None:
            kw = {}

            if self.endpoint is not None:
                kw['endpoint_url'] = self.endpoint
            if self.region is not None:
                kw['region_name'] = self.region

            dynamodb = boto3.resource('dynamodb', **kw)
            self._boto_table = dynamodb.Table(self.table)

        return self._boto_table

    def boto_client(self):
        """
        """
        if self._boto_client is None:
            kw = {}

            if self.endpoint is not None:
                kw['endpoint_url'] = self.endpoint
            if self.region is not None:
                kw['region_name'] = self.region

            self._boto_client = boto3.client('dynamodb', **kw)

        return self._boto_client