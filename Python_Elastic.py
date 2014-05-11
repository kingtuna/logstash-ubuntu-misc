#!/usr/bin/env python
from __future__ import print_function
from elasticsearch import Elasticsearch
import logging
from dateutil.parser import parse as parse_date

"""
Querying Elastic search for threat data 
Most of this is copied from: 
http://blog.arisetyo.com/getting-started-with-python-elasticsearch-client/
"""

EHOST='HOST'
INDEX='INDEX'

##### Print The Generic Hits 
def print_hits(results, facet_masks={}):
    " Simple utility function to print results of a search query. "
    print('=' * 80)
    print('Total %d found in %dms' % (results['hits']['total'], results['took']))
    if results['hits']['hits']:
        print('-' * 80)
    for hit in results['hits']['hits']:

        # get created date for a repo and fallback to authored_date for a commit
        created_at = parse_date(hit['_source'].get('created_at', hit['_source']['@timestamp']))
        print('/%s/%s/%s (%s): %s' % (
                hit['_index'], hit['_type'], hit['_id'],
                created_at.strftime('%Y-%m-%d'),
                hit['_source']['message'].replace('\n', ' ')))

    for facet, mask in facet_masks.items():
        print('-' * 80)
        for d in results['facets'][facet]['terms']:
            print(mask % d)
    print('=' * 80)
    print()

##### Print The SSH Counts
def print_ssh_counts(results, facet_masks={}):
    " Simple utility function to print results of a search query. "
    print('=' * 80)
    print('SSH Bruteforcers')
    if results['hits']['hits']:
        print('-' * 80)
    for hit in results['hits']['hits']:
        print(hit)
        # get created date for a repo and fallback to authored_date for a commit
        created_at = parse_date(hit['_source'].get('created_at', hit['_source']['@timestamp']))
        print('/%s/%s/%s (%s): %s' % (
                hit['_index'], hit['_type'], hit['_id'],
                created_at.strftime('%Y-%m-%d'),
                hit['_source']['message'].replace('\n', ' ')))

    for facet, mask in facet_masks.items():
        print('-' * 80)
        for d in results['facets'][facet]['terms']:
            print(mask % d)
    print('=' * 80)
    print()
    
##### Print The SSH Usernames
def print_ssh_usernames(lresult, facet_masks={}):
    " Simple utility function to print results of a search query. "
    print('=' * 80)
    print('SSH Usernames and Passwords')
    print('-' * 80)
    for results in lresult:
        for hit in results['hits']['hits']:
            #print(hit['_source']['user'],'\n')
            # get created date for a repo and fallback to authored_date for a commit
            created_at = parse_date(hit['_source'].get('created_at', hit['_source']['@timestamp']))
            try:
                print('%s: %s' % (hit['_source']['user'],hit['_source']['pass']))
            except:
                pass
        for facet, mask in facet_masks.items():
            print('-' * 80)
            for d in results['facets'][facet]['terms']:
                print(mask % d)
    print('=' * 80)
    print()

# by default we don't sniff, ever
es = Elasticsearch(host=EHOST, port=9200)

##### GET The SSH Counts
result = es.search(
    index=INDEX,
    body={
          'size': 0,
      'query': {
        'filtered': {
          'filter': {
              'query': {
                'filtered': {
                  'filter': {
                    'term': {
                      '_type': 'SSHPOT_sshlog'
                  }
                }
              }
            }
          }
        }
      },
    'facets': {
        'terms': {
          'terms': {
            'field': 'id.orig_h',
            'order': 'count'
          }
        }
      }
    }
    )

print_ssh_counts(result,{'terms': '%(term)15s: %(count)3d'})


##### Print GET Usernames and Passwords
result = es.search(
    index=INDEX,
    body={
    'size': 0,
      'query': {
        'filtered': {
          'filter': {
              'query': {
                'filtered': {
                  'filter': {
                    'term': {
                      '_type': 'SSHPOT_sshlog'
                  }
                }
              }
            }
          }
        }
      }
    }
)
size = result['hits']['total']
"""how many times to run the loop each loop has 500 results""" 
qsize = 500
lresult = []

if size == 0:
    pass
elif size <= qsize:
    itertations = 1
else:
    iterations = (size/qsize)+1
    
for i in range(0,iterations):
    start = (qsize*i)
    
    result = es.search(
    index=INDEX,
    body={
    'from': start, 'size': qsize,
      'query': {
        'filtered': {
          'filter': {
              'query': {
                'filtered': {
                  'filter': {
                    'term': {
                      '_type': 'SSHPOT_sshlog'
                  }
                }
              }
            }
          }
        }
      }
    }
    )
    lresult.append(result)

print_ssh_usernames(lresult)