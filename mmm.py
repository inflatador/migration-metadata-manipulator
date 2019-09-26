#!/usr/bin/env python3
# Migration Metadata Manipulator, mmm.py
# given an account, region, and argument (all or live),
# shows, adds, or removes all server metadata on that account
# related to migrations
# version: 0.0.2a
# Copyright 2019 Brian King
# License: Apache

from datetime import tzinfo, timedelta, datetime, date
from getpass import getpass
import json
import keyring
import logging
from netmiko import Netmiko
import os
import plac
import requests
import sys
import time
import uuid

def find_endpoints(auth_token, headers, region, desired_service="cloudServersOpenStack"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]

    for service in endpoints:
        if desired_service == service["name"] and region == service["region"]:
            desired_endpoint = service["publicURL"]

    return desired_endpoint

def getset_keyring_credentials(username=None, password=None):
    #Method to retrieve credentials from keyring.
    print (sys.version_info.major)
    username = keyring.get_password("mmr", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("mmr", 'username', username)
            print ("Username value saved in keychain as mmr username.")
        elif sys.version_info.major >= 3:
            username = input("Enter Rackspace Username: ")
            keyring.set_password("mmr", 'username', username)
            print ("Username value saved in keychain as mmr username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
        password = keyring.get_password("mmr", "password")
    if not password:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("mmr", 'password' , password)
        print ("API key value saved in keychain as mmr password.")
    return username, password
# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]

    headers = ({'content-type': 'application/json', 'Accept': 'application/json',
    'X-Auth-Token': auth_token})

    return auth_token, headers


def get_srv_list(cs_endpoint, headers, region):
    srv_route = "{}/servers".format(cs_endpoint)
    print("Retrieving list of {} servers from API...".format(region))
    srv_list = requests.get(url=srv_route, headers=headers)
    num_srvs = (len(srv_list.json()["servers"]))
    srv_list = srv_list.json()["servers"]
    print ("Found {} servers in {} region.".format(num_srvs, region))
    return srv_list

def check_for_metadata(cs_endpoint, headers, region, srv_list):
    #These tags are all related to live migration
    mig_metadata = ['no_dc_migration', 'skip_all_migrations',
                    'no_standard_migrate', 'no_live_migrate',
                    'allow_live_migrate'
                    ]

    print (f"Checking all {region} servers for migration metadata...")
    for srv in srv_list:
        srv_name = srv["name"]
        srv_url = srv["links"][0]["href"]
        print ("Retrieving metadata info for server {}".format(srv_name))
        srv_info = requests.get(url=srv_url,headers=headers)
        # print (srv_info.json().keys())
        srv_metadata = srv_info.json()["server"]["metadata"]
        srv_mig_metadata = []
        # print (srv_metadata.keys())
        for mig_metadatum in mig_metadata:
            if mig_metadatum in srv_metadata.keys():
                srv_mig_metadata.append(mig_metadatum)
        if srv_mig_metadata:
            print (f"Server {srv_name} has migration metadata"
                   f"{srv_mig_metadata} set.")
        else:
            print (f"Server {srv_name} has no migration metadata. It is "
            "allowed to live-migrate.")



# Plac's way of adding help messages

@plac.annotations(
    region=plac.Annotation("Rackspace Cloud region"),
    action=plac.Annotation("What to do with the migration metadata", choices=["view","set", "remove"])
                )

def main(region, action):

    username, password = getset_keyring_credentials()

    auth_token, headers = get_auth_token(username, password)

    cs_endpoint = find_endpoints(auth_token, headers, region,
              desired_service="cloudServersOpenStack")

    srv_list = get_srv_list(cs_endpoint, headers, region)

    check_for_metadata(cs_endpoint, headers, region, srv_list)


if __name__ == '__main__':
    plac.call(main)
