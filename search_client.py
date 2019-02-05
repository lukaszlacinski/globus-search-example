#!/usr/bin/env python

"""
Register your own app at developers.globus.org. Configure as follows:
Native App:
    * "Redirect URLs" -- Set to "https://auth.globus.org/v2/web/auth-code".
        You can setup your own server for distributing auth codes if you wish.
    * Scopes:
        [openid profile urn:globus:auth:scope:transfer.api.globus.org:all]
        openid and profile are required for auth, transfer.api.globus.org
        for transfers.
    * Check "Native App".
Confidential App [Client Credentials Grant]:
    * "Redirect URLs" -- Set to "https://auth.globus.org/v2/web/auth-code".
        Confidential apps also allow you to setup your own server for three-
        legged-auth with auth.globus.org if you wish. You may therefore put
        https://example.com/oauth_callback/ instead.
    * Scopes:
        [urn:globus:auth:scope:transfer.api.globus.org:all]
        Only transfer is required, since your bot will be using client_secret
        to authenticate. [openid profile] are required if you setup your own
        three-legged-auth server and want to allow users to login to it.
    * Uncheck "Native App".

"""

from __future__ import print_function
import os
import sys
import argparse
import webbrowser
import json
import globus_sdk
from globus_sdk.exc import TransferAPIError
import requests
from pprint import pprint
# Both Native App and Client Credential authentication require Client IDs.
# Create your app at developers.globus.org. The following id is for testing
# only and should not be relied upon (You should create your own app).
CLIENT_ID = '6c1629cf-446c-49e7-af95-323c6412397f'

# Client Secret is only needed for Confidential apps. Make your app
# confidential instead of native by _not_ checking the 'Native App' checkbox
# on developers.globus.org for your app.
CLIENT_SECRET = ''

# Native is better for user machines, where the user is capable of hitting
# a browser to get an authentication code. Native only stores temporary
# access tokens (unless you enable refresh tokens), and does not require
# safeguarding client secrets.
#
# Client Credentials grant requires storing a 'client_secret', which does
# not require a browser or user intervention, but does require safeguarding
# the client_secret. Use Confidential on servers or trusted machines.
# *Notice*: A confidential app is a bot which acts on your behalf. You will
# need to give it permission to access your shared endpoint. You can do so
# with globus-cli via:
# globus endpoint permission create
#   --identity <client_id>@clients.auth.globus.org
#   <Your shared_endpoint UUID>:/
#   --permissions rw
# (Your bot's identity will always match the client id for your
# app + '@clients.auth.globus.org')
#
# You can also go to globus.org/app/endpoints?scope=shared-by-me and under
# "Identity/E-mail" set: "<client_id>@clients.auth.globus.org"
APP_AUTHENTICATORS = ('native', 'client-credentials')

# Default is native for this script.
AUTHENTICATION = 'native'

# Redirect URI specified when registering a native app
REDIRECT_URI = 'https://auth.globus.org/v2/web/auth-code'

# For this example, we will be liberal with scopes.
SCOPES = ('openid email profile '
          'urn:globus:auth:scope:search.api.globus.org:search')
TOKEN_FILE = 'refresh-tokens.json'


get_input = getattr(__builtins__, 'raw_input', input)


def load_tokens_from_file(filepath):
    """Load a set of saved tokens."""
    with open(filepath, 'r') as f:
        tokens = json.load(f)

    return tokens


def save_tokens_to_file(filepath, tokens):
    """Save a set of tokens for later use."""
    with open(filepath, 'w') as f:
        json.dump(tokens, f)


def update_tokens_file_on_refresh(token_response):
    """
    Callback function passed into the RefreshTokenAuthorizer.
    Will be invoked any time a new access token is fetched.
    """
    save_tokens_to_file(TOKEN_FILE, token_response.by_resource_server)


def is_remote_session():
    """
    Check if this is a remote session, in which case we can't open a browser
    on the users computer. This is required for Native App Authentication (but
    not a Client Credentials Grant).
    Returns True on remote session, False otherwise.
    """
    return os.environ.get('SSH_TTY', os.environ.get('SSH_CONNECTION'))


def eprint(*args, **kwargs):
    """Same as print, but to standard error"""
    print(*args, file=sys.stderr, **kwargs)


def do_native_app_authentication(client_id, redirect_uri,
                                 requested_scopes=None):
    """
    Does a Native App authentication flow and returns a
    dict of tokens keyed by service name.
    """
    client = globus_sdk.NativeAppAuthClient(client_id=client_id)
    # pass refresh_tokens=True to request refresh tokens
    client.oauth2_start_flow(
            requested_scopes=requested_scopes,
            redirect_uri=redirect_uri,
            refresh_tokens=True)

    url = client.oauth2_get_authorize_url()

    print('Native App Authorization URL: \n{}'.format(url))

    if not is_remote_session():
        # There was a bug in webbrowser recently that this fixes:
        # https://bugs.python.org/issue30392
        if sys.platform == 'darwin':
            webbrowser.get('safari').open(url, new=1)
        else:
            webbrowser.open(url, new=1)

    auth_code = get_input('Enter the auth code: ').strip()

    token_response = client.oauth2_exchange_code_for_tokens(auth_code)

    # return a set of tokens, organized by resource server name
    return token_response.by_resource_server


def get_native_app_authorizer(client_id, service):
    tokens = None
    try:
        # if we already have tokens, load and use them
        tokens = load_tokens_from_file(TOKEN_FILE)
    except:
        pass

    if not tokens:
        tokens = do_native_app_authentication(
                client_id=client_id,
                redirect_uri=REDIRECT_URI,
                requested_scopes=SCOPES)
        try:
            save_tokens_to_file(TOKEN_FILE, tokens)
        except:
            pass

    tokens = tokens[service]

    auth_client = globus_sdk.NativeAppAuthClient(client_id=client_id)

    return globus_sdk.RefreshTokenAuthorizer(
            tokens['refresh_token'],
            auth_client,
            access_token=tokens['access_token'],
            expires_at=tokens['expires_at_seconds'],
            on_refresh=update_tokens_file_on_refresh)


def do_client_credentials_app_authentication(client_id, client_secret):
    """
    Does a client credential grant authentication and returns a
    dict of tokens keyed by service name.
    """
    client = globus_sdk.ConfidentialAppAuthClient(
            client_id=client_id,
            client_secret=client_secret)
    token_response = client.oauth2_client_credentials_tokens()

    return token_response.by_resource_server


def get_confidential_app_authorizer(client_id, client_secret):
    tokens = do_client_credentials_app_authentication(
            client_id=client_id,
            client_secret=client_secret)
    transfer_tokens = tokens['transfer.api.globus.org']
    transfer_access_token = transfer_tokens['access_token']

    return globus_sdk.AccessTokenAuthorizer(transfer_access_token)


def main():
    search_index = '3e117028-2513-4f5b-b53c-90fda3cd328b'
    service = 'search.api.globus.org'

    authorizer = get_native_app_authorizer(client_id=CLIENT_ID, service=service)

    sc = globus_sdk.SearchClient(authorizer=authorizer)
    r = sc.search(search_index, '*')
    #r = sc.delete_subject(index_id=search_index, subject='globus://e56c36e4-1063-11e6-a747-22000bf2d559/data/papers/clipping_10428503.pdf')
    print(json.dumps(r.data, indent=4))


if __name__ == '__main__':
    main()
