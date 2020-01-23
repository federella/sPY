import yaml
import argparse
import shodan
import subprocess
from bucketbrute import *
from banner import *
SHODAN_KEY = ""


#initialize shodan keys from config.yaml file
def init_keys(switch):
    global SHODAN_KEY
    if switch == 'yaml':
        try:
            data = yaml.safe_load(open('config.yaml'))
            SHODAN_KEY = data['shodan']
        except:
            print("Initialization error: please check your config file")
    else:
        SHODAN_KEY = switch

#query shodan for KEY and write to file/standard output
def query_shodan(key, output):
    shodan_banner()
    try:
        api = shodan.Shodan(SHODAN_KEY)
        results = api.search(key)
        print_shodan_results(results, output)
    except shodan.APIError as e:
        print('Error: {}'.format(e))

#
def print_shodan_results(data, output):
    string="SHODAN\n" 
    for match in data['matches']:
        date, hour = match['timestamp'].split('T')
        string += "\n\tFOUND: {}\n \tTIMESTAMP: {} {}\n\t".format(match['ip_str'],date,hour)
        if len(match['hostnames']) > 0:
            string+="HOST: "
            for i in range(len(match['hostnames'])):
                if i > 0:
                    string += ", "
                string += "{}".format(match['hostnames'][i])
            string += "\n"
    string += "\nTOTAL MATCHES: {}".format(data['total'])
    if output == 'stdout':
        print(string)
    else:
        with open(outfile,'w') as f:
            f.write(string)


def query_gcpbb(keyword, outfile = None):
    gcpbb_banner()
    search_buckets(keyword)
    #  = ["python", "gcpbucketbrute.py", "-k", keyword,"-u"]
    # if outfile != None:
        # parameters += ["-o", outfile]
    # print("GCPBUCKETBRUTE\n")
    # subprocess.call(parameters)
    
def init_args():
    parser = argparse.ArgumentParser(description="Query Shodan for <keyword>")
    parser.add_argument('keyword', help='search keyword')
    parser.add_argument('--key', dest='api_key', type=str, nargs='?', default='yaml',help = 'shodan api key [default: reads from config.yaml file]')
    parser.add_argument('--out', dest='output', type=str, default='stdout', nargs='?', help = 'output file [default: standard output]')
    #parser.add_argument('--op', dest='operation', choices=['shodan', 'gcpbucket'], help = 'query only one between [shodan / gcpbucket]')
    args = parser.parse_args()
    main(args)
    #print(args.

    
def main(args):
    init_keys(args.api_key)
    query_shodan(args.keyword,args.output)
    if args.output: 
        query_gcpbb(args.keyword, outfile=args.output)
    else:
         query_gcpbb(args.keyword)
        
    
    
if __name__ == "__main__":
    spy_banner()
    init_args()
