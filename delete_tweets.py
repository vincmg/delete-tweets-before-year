#!/usr/bin/env python3

import argparse
import datetime
import sys
import signal
import json
import requests
from rauth import OAuth1Service

# global so we can print it in sig handler
current_index = 0


def sig_handler(sig, frame):
    print("index of last tweet requested before interrupt:", current_index)
    exit()


def import_secrets(filename):
    with open(filename, 'r') as secrets:
        consumer_key = secrets.readline().strip()
        consumer_secret = secrets.readline().strip()
    return consumer_key, consumer_secret


def import_json(filename):
    with open(filename, 'r') as infile:
        text = infile.read()
    return json.loads(text)


def get_tweet_id_list(filename, min_year):
    tweets = import_json(filename)

    ids_to_delete = []

    for tweet_data in tweets:
        tweet = tweet_data['tweet']
        if int(tweet['created_at'].split()[-1]) < min_year:
            ids_to_delete.append(tweet['id'])
    return ids_to_delete


def delete_tweets(secrets, year, tweet_file, index):
    consumer_key, consumer_secret = import_secrets(secrets)
    tweets_to_delete = get_tweet_id_list(tweet_file, year)

    twitter = OAuth1Service(
        name='twitter',
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authorize',
        base_url='https://api.twitter.com/1.1/')

    request_token, request_token_secret = twitter.get_request_token()

    authorize_url = twitter.get_authorize_url(request_token)
    print('Visit this URL in your browser: {url}'.format(url=authorize_url))
    pin = input('Enter PIN from browser: ')
    session = twitter.get_auth_session(request_token,
                                       request_token_secret,
                                       method='POST',
                                       data={'oauth_verifier': pin})

    error_count = 0
    delete_count = 0

    for i, tweet in enumerate(tweets_to_delete[index:]):
        global current_index
        current_index = i + index
        r = session.post('statuses/destroy/{}.json'.format(tweet), data=dict())
        if r.status_code != 200:
            error_count += 1
            print(r.status_code, r.text, file=sys.stderr)

            if r.status_code == 429:  # exceeded rate limit
                limit_ceil = r.headers['x-rate-limit-limit']
                limit_rem = r.headers['x-rate-limit-remaining']
                secs_until_reset = int(r.headers['x-rate-limit-reset'])

                print("limit exceeded.\n\treq limit {}\n\treq remaining {}\n\tseconds until reset {}".format(
                    limit_ceil, limit_rem, secs_until_reset), file=sys.stderr)

                now = time.time()
                resume_time = now + secs_until_reset
                resume_time_str = datetime.fromtimestamp(
                    resume_time).isoformat(' ')
                print("script will resume at", resume_time_str, file=sys.stderr)
                time.sleep(secs_until_reset)
                continue
        else:
            delete_count += 1
            rjson = r.json()
            print("deleted tweet:\n\tid {}\n\tdate {}\n\ttext {}".format(
                rjson['id'], rjson['created_at'], rjson['text'].replace('\n', '\n\t')))

    print("success:", delete_count)
    print("error:", error_count)
    print("index of last tweet requested:", i)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sig_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--secrets', required=True,
                        help='path to file with consumer api key and secret key')
    parser.add_argument('-y', '--year', required=True,
                        help='cutoff point for delete script. all tweets made before the start of this year will be deleted')
    parser.add_argument('-f', '--file', required=True,
                        help='path to tweet json file from your twitter archive')
    parser.add_argument('-i', '--index', default=0,
                        help='start at the ith entry in the tweet json file. useful when resuming the script after it was interrupted')
    args = parser.parse_args()
    secrets = args.secrets
    year = int(args.year)
    filename = args.file
    index = int(args.index)

    delete_tweets(secrets, year, filename, index)
