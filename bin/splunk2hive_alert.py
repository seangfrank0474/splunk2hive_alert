#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Custom Splunk Alerts to The Hive
# Sean Frank, Cyberdefense - Incident Response
# Created - 01/26/2021 Modified - 01/26/2021

from __future__ import print_function
from __future__ import unicode_literals

import requests
import sys
import json
import time
import uuid
import os
import gzip
import csv
import string
import re
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

def Splunk2HiveArtifactParse(key, value, observ_keys_list, artifacts):
    for ob_iter in observ_keys_list:
        if key == ob_iter:
            if re.search(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', value) is not None:
                d_type = 'ip'
            elif re.search(r'([\w\-]+\.){0,}([\w\-]+\.[a-zA-Z]{1,63})', value) is not None:
                d_type = 'domain'
            elif re.search(r'(http(s)?\:\/\/([\w\-]+\.){0,}([\w\-]+\.[a-zA-Z]{1,63}))', value) is not None:
                d_type = 'url'
            elif re.search(r'(?:[0-9a-fA-F]{32,64})', value) is not None:
                d_type = 'hash'
            else:
                d_type = 'other'
            iter_value = value.split(' ')
            for i in iter_value:
                artifacts.append(AlertArtifact(dataType = d_type, data = i))
    return artifacts

def Splunk2HiveAPI(csv_rows, config):
    url = config.get('url') 
    splunk_api = config.get('api_key')
    cert_check = config.get('cert_check')
    observable_keys=config.get('obsrv_key')
    api = TheHiveApi(url, splunk_api, cert=cert_check)
    refnum = str(uuid.uuid4())[0:12]
    sourceRef = "Hive_Alert_ref-"+refnum
    #observable_keys = 'nsp_src_ip nsp_dest_ip'
    #api = TheHiveApi('https://example.com/thehive', 'APIKeyGoesHere', cert=False)
    parsed_rows = {key: value for key, value in csv_rows.items()}
    artifacts = []
    for key, value in parsed_rows.items():
        observ_keys_list = observable_keys.split(' ')
        artifacts = Splunk2HiveArtifactParse(key, value, observ_keys_list, artifacts)
    alert = Alert(
        title = config.get('title'),
        description = config.get('description', "No description provided."),
        tags = [] if config.get('tags') is None else config.get('tags').split(","),
        severity = int(config.get('severity', 2)),
        tlp = int(config.get('tlp', -1)),
        type = 'Splunk_Notable_Event',
        artifacts = artifacts,
        source = config.get('source', "Splunk"),
        sourceRef = sourceRef
    )
    
    # Create the Alert
    print('Create Alert')
    print('-----------------------------')
    id = None
    response = api.create_alert(alert)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)

    # Get all the details of the created alert
    print('Get created alert {}'.format(id))
    print('-----------------------------')
    response = api.get_alert(id)
    if response.status_code == requests.codes.ok:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))

if __name__ == "__main__":
    # make sure we have the right number of arguments - more than 1; and first argument is "--execute"
	if len(sys.argv) > 1 and sys.argv[1] == "--execute":
		# read the payload from stdin as a json string
		payload = json.loads(sys.stdin.read())
		# extract the results file and alert config from the payload
		config = payload.get('configuration')
		results_file = payload.get('results_file')
		if os.path.exists(results_file):
			try:
				with gzip.open(results_file) as file:
					reader = csv.DictReader(file)
					# iterate through each row, creating a alert for each and then adding the observables from that row to the alert that was created
					for csv_rows in reader:
						Splunk2HiveAPI(csv_rows, config)
				sys.exit(0)
			except IOError as e:
				print("FATAL Results file exists but could not be opened/read", file=sys.stderr)
				sys.exit(3)
		else:
			print("FATAL Results file does not exist", file=sys.stderr)
			sys.exit(2)
	else:
		print("FATAL Unsupported execution mode (expected --execute flag)", file=sys.stderr)
		sys.exit(1)
