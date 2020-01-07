import os
import argparse
import re
import requests
import slack

print("====== Welcome to API Whoami ======\n")

ap = argparse.ArgumentParser()
ap.add_argument("-a", "--apikey", required=True, help="Define apikey to lookup")
ap.add_argument("-v", "--verbose", action="store_true", help="We display the output of all API calls after the Overview")
args = vars(ap.parse_args())
api_key = args['apikey']
verbose = args['verbose']
print("[*] Guessing API key: {}".format(api_key))
guess_prefix_dict = {
    "slack-bot" : "xoxb-",
    "slack-user": "xoxp-",
    "slack-work": "xoxa-2",
    "slack-web": "xoxc-",
    "slack-unknown": "xoxs-"
}

def main():
    platform = guess_api_key(api_key)
    if not platform:
        print("[X] api key not recongised")
        exit()

    print("[\u2713] Guessing API key done.. Platform is {}".format(platform))
    print("[*] Trying to get details for API key.")
    info = get_more_info(api_key, platform)
    if len(info) == 0:
        print("[X] No details found using this key. Im sorry")
        exit()
    print("[\u2713] API Key Overview: \n{}".format(info['overview']))
    if verbose:
        print("[\u2713] Below details were found: \n{}".format(info if 'summary' not in info else info['summary']))
        print("[*] Thanks for using API-Whoami.")
    else:
        print("[*] Thanks for using API-Whoami. If you would like to see all the results of the APIs used, try --verbose")

def get_more_info(api_key, platform):
    """
    Here we try use the key or get some information from the key by
    hitting platform specific endpoints that may leak some info to us.
    """
    results = {}
    if platform.startswith('slack-'):
        results.update(_get_more_slack_info(api_key, platform))

    return results

def _get_more_slack_info(api_key, platform):
    client = slack.WebClient(token=api_key)
    # We start a couple api calls to try get a feel for what we can do with this api key
    data = {}
    try:
        ## auth_test : https://slack.com/api/auth.test => check response at https://api.slack.com/methods/auth.test
        ## this works with both bot and user api tokens
        data['auth_test'] = client.auth_test().data
    except slack.errors.SlackApiError as e:
        data['auth_test'] =  e.response

    if 'error' in data['auth_test']:
        return _intepret_responses_slack(data, platform)
    try:
        ## users_info : https://slack.com/api/users.info => check response at https://api.slack.com/methods/users.info
        ## note: only works with user token type with `users:read` scope, and bot token type with `bot` scope
        if 'user_id' in data['auth_test']:
            data['users_info'] = client.users_info(user=data['auth_test']['user_id']).data
        else:
            data['users_info'] = client.users_info(user="asdzxciu").data
    except slack.errors.SlackApiError as e:
        data['users_info'] = e.response

    try:
        ## conversations_info : https://slack.com/api/conversations.info => check response at https://api.slack.com/methods/conversations.info
        ## note: only works with user token type with `channels:read, groups:read, im:read, mpim:read` scope, and bot token type with `bot` scope
        data['conversations_info'] = client.conversations_info(channel="ASDJALKSBNCX123")
    except slack.errors.SlackApiError as e:
        data['conversations_info'] = e.response

    try:
        ## users_identity : https://slack.com/api/users.identity => check response at https://api.slack.com/methods/users.identity
        ## note: only works with user token type with `identity.basic` scope and NOT bot token type.
        data['users_identity'] = client.users_identity()
    except slack.errors.SlackApiError as e:
        data['users_identity'] = e.response
    except slack.errors.BotUserAccessError as e:
        data['users_identity'] = {'token' :'Bot Token cannot user users_identity API'}

    return _intepret_responses_slack(data, platform)

def _intepret_responses_slack(data, platform):
    d = {}
    d['raw'] = data
    d['overview'] = "▶ Slack API Token Overview:\n\t\tToken Type: {key}\n\t\t".format(key=platform.split('-')[1].upper())
    if 'error' in data['auth_test']:
        d['overview'] += "Permissions: {perms}\n\t\t".format(perms="This token has been revoked already.")
    overview = {}
    d['summary'] = " ▼ Slack API Token Summary:"
    for key in data.keys():
        if 'error' in data[key] and data[key]['error'] == 'missing_scope':
            overview['permissions_provided'] = data[key]['provided']
        d['summary'] += _add_api_response_to_summary(key, data[key])
    if 'permissions_provided' in overview:
        d['overview'] += "Permissions: {perms}\n\t\t".format(perms=overview['permissions_provided'])
    if 'users_identity' in data and data['users_identity'].get('token'):
        d['overview'] += "Permissions: {perms}\n\t\t".format(perms="Bots have many permissions")
        d['overview'] += "Read about the allowed bot permissions here: https://api.slack.com/bot-users#methods"
    return d

def _add_api_response_to_summary(api, resp, heading=True):
    s = "\n\t▶ API {} returned:\n\t\t".format(api) if heading else " "
    for k in resp.keys():
        if type(resp[k]) == bool:
            # this if is specifically slack based; we may need to add for others
            if k == 'ok' or not resp[k]:
                continue
            s += (' '.join(k.split('_')))+'\n\t\t'
        elif type(resp[k]) == dict:
            s += _add_api_response_to_summary(k, resp[k], heading=False)
        else:
            s += "{}: {}\n\t\t".format(k, resp[k])
    return s

## we should consider some bot only api calls
### https://api.slack.com/bot-users#methods

## interesting slack api calls to come back to look at:
### https://api.slack.com/methods/team.integrationLogs
### https://api.slack.com/methods/team.accessLogs


def guess_api_key(api_key):
    """
    Here we guess by some heuristics what platform/company this API
    key belongs to.
    """
    # print("**** starting initial guesses ****")
    for platform, key_pattern in guess_prefix_dict.items():
        p = re.compile(key_pattern+'\w+', re.IGNORECASE)
        m = p.match(api_key)
        if m:
            return platform
    return None

class Platform(object):

    def __init__(self, platform, api_key):
        self.platform = platform
        self.key = api_key

    def get_more_info(self,):
        pass




if __name__ == "__main__":
    main()