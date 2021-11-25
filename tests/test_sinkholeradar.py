
from sinkholeradar import database_stuff
from mongoengine import *
from mongoengine.connection import disconnect
import mongomock
import os
import requests
import mongomock
import pytest
from dotenv import load_dotenv

load_dotenv()


class SinkholeObject(Document):
    param = StringField()

class TestSinkhole():
    @classmethod
    def setupdb(cls):
        connect('sinkholeradartest', host='')

    @classmethod
    def kill_connection(cls):
        disconnect()

    def test_input(self):
        per = SinkholeObject(param='testtest')
        per.save()

        new_pers = SinkholeObject.objects().first()
        assert new_pers.param == 'testtest'

    def test_sinkhole_header(self):
        ipaddr = 'http://134.209.227.14'
        expected_x_header = 'X-Sinkhole'

        resp = requests.get(ipaddr)
        ret_headers = resp.headers

        assert expected_x_header in ret_headers

    def test_riskiq_api(self):
        url = 'https://api.riskiq.net/pt/v2/dns/passive'
        api_username = os.getenv('RISKIQ_USERNAME')
        api_key = os.getenv('RISKIQ_APIKEY')
        auth = (api_username, api_key)
        data = {'query': 'test'}
        apiresp = requests.get(url, auth=auth, json=data)

        assert apiresp.status_code == 200


