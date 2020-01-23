#!/usr/bin/env python3
import argparse
import time
import multiprocessing
import json
import sys
import textwrap
from functools import partial
from datetime import datetime, timedelta
import requests
import google.oauth2.credentials
from google.cloud import storage
from google.oauth2 import service_account

SUBPROCESSES = 5


def generate_bucket_permutations(keyword):
    permutation_templates = [
        '{keyword}-{permutation}',
        '{permutation}-{keyword}',
        '{keyword}_{permutation}',
        '{permutation}_{keyword}',
        '{keyword}{permutation}',
        '{permutation}{keyword}'
    ]
    with open('./permutations.txt', 'r') as f:
        permutations = f.readlines()
        buckets = []
        for perm in permutations:
            perm = perm.rstrip()
            for template in permutation_templates:
                generated_string = template.replace('{keyword}', keyword).replace('{permutation}', perm)
                buckets.append(generated_string)

    buckets.append(keyword)
    buckets.append('{}.com'.format(keyword))
    buckets.append('{}.net'.format(keyword))
    buckets.append('{}.org'.format(keyword))
    buckets = list(set(buckets))
    # Strip any guesses less than 3 characters or more than 63 characters
    for bucket in buckets:
        if len(bucket) < 3 or len(bucket) > 63:
            del buckets[bucket]

    print('\nGenerated {} bucket permutations.\n'.format(len(buckets)))
    return buckets


def search_buckets(keyword, out_file=None):
    buckets = generate_bucket_permutations(keyword)
    subprocesses = []
    start_time = time.time()
    #client = None 
    for i in range(0, SUBPROCESSES):
        start = int(len(buckets) / SUBPROCESSES * i)
        end = int(len(buckets) / SUBPROCESSES * (i+1))
        permutation_list = buckets[start:end]
        subproc = Worker(None, print, permutation_list, out_file)
        subprocesses.append(subproc)
        subproc.start()
    cancelled = False
    while len(subprocesses) > 0:
        try:
            subprocesses = [s.join() for s in subprocesses if s is not None]
        except KeyboardInterrupt:
            cancelled = True
            print('Ctrl+C pressed, killing subprocesses...')
    if not cancelled:
        end_time = time.time()
        scanning_duration = timedelta(seconds=(end_time - start_time))
        d = datetime(1, 1, 1) + scanning_duration
        if d.day - 1 > 0:
            print('\nScanned {} potential buckets in {} day(s), {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.day-1, d.hour, d.minute, d.second))
        elif d.hour > 0:
            print('\nScanned {} potential buckets in {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.hour, d.minute, d.second))
        elif d.minute > 0:
            print('\nScanned {} potential buckets in {} minute(s) and {} second(s).'.format(len(buckets), d.minute, d.second))
        else:
            print('\nScanned {} potential buckets in {} second(s).'.format(len(buckets), d.second))

    print('\nGracefully exiting!')
    # if args.out_file:
        # print = normal_print


class Worker(multiprocessing.Process):
    def __init__(self, client, print, permutation_list, out_file):
        multiprocessing.Process.__init__(self)
        self.client = client
        self.print = print
        self.permutation_list = permutation_list
        self.out_file = out_file

    def run(self):
        try:
            for bucket_name in self.permutation_list:
                if self.check_existence(bucket_name):
                    self.check_permissions(bucket_name)
        except KeyboardInterrupt:
            return

    def check_existence(self, bucket_name):
        try:
            # Check if bucket exists before trying to TestIamPermissions on it
            response = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(bucket_name))
            if response.status_code not in [400, 404]:
                return True
            return False
        except:
            return

    def check_permissions(self, bucket_name):
        authenticated_permissions = []
        unauthenticated_permissions = []
       
        unauthenticated_permissions = requests.get('https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(bucket_name)).json()

        if unauthenticated_permissions.get('permissions'):
            self.print('\n    UNAUTHENTICATED ACCESS ALLOWED: {}'.format(bucket_name))
            if 'storage.buckets.setIamPolicy' in unauthenticated_permissions['permissions']:
                self.print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
            if 'storage.objects.list' in unauthenticated_permissions['permissions']:
                self.print('        - UNAUTHENTICATED LISTABLE (storage.objects.list)')
            if 'storage.objects.get' in unauthenticated_permissions['permissions']:
                self.print('        - UNAUTHENTICATED READABLE (storage.objects.get)')
            if 'storage.objects.create' in unauthenticated_permissions['permissions'] or 'storage.objects.delete' in unauthenticated_permissions['permissions'] or 'storage.objects.update' in unauthenticated_permissions['permissions']:
                self.print('        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
            self.print('        - ALL PERMISSIONS:')
            self.print(textwrap.indent('{}\n'.format(json.dumps(unauthenticated_permissions['permissions'], indent=4)), '            '))

        if not (unauthenticated_permissions.get('permissions')):
            self.print('    EXISTS: {}'.format(bucket_name))


