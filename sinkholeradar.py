import requests
import mmh3 
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from sinkholeradar.modules import shodan_results, riskiq_results
from dataclasses import dataclass
import pymongo

load_dotenv()

# Items to get from URL :
# Check for 'sinkhole' [X]
# Get hash [X]
# Check tag to get vendor name [X]
# Get screenshot [O]
# Get open ports [X]
# Get domain resolutions [O]
# Dates: current (today) & first_seen [O]


class SinkholeRadar:

    def __init__(self, target: str):
        self.target = target
        
    def process_ipaddr(self, target):
        
        print(f'[+] Verifying {target} is a sinkhole...\n')
        self.prepend_http = 'http://'
        self.response = requests.get(self.prepend_http + target)
        self.http_hash = mmh3.hash(self.response.text)
        
        if 'X-Sinkhole' in self.response.headers or 'sinkhole' in self.response.content.decode('utf-8'):
            print('[+] Possible sinkhole identified!\n')
            print(f'[+] http.html_hash: {self.http_hash}')

        else:
            print('[!] This may not be a sinkhole. Try a manual search.')
            raise SystemExit

    def get_vendor_info(self):

        soup = BeautifulSoup(self.response.text, 'lxml')
        head_tags = 'h1'

        for tag in soup.find_all(head_tags):
            print(tag.name + ' -> ' + tag.text.strip())
            print()
            find_message = 'Did you find the vendor name?\n[Y] Yes [N] No: '
            print()
            while True:
                user_input = input(find_message)
                response = user_input.strip()[0].lower()
                if response not in ['y', 'n']:
                    print(f'[-] Response {response} not identified')
                    continue
                if response == 'n':
                    print('Vendor information may be in a different HTML tag, moving on...')
                    break
                if response == 'y':
                    self.vendor_name = str(input('Vendor name: '))
                    print(f'[+] Vendor {self.vendor_name} saved !\n')
                    break
                print()

    def connect_database(self):
        conn_mongo_cli = pymongo.MongoClient()
        db = conn_mongo_cli['sinkholeradardb']
        db_collection = db['sinkholeradar']

        sys_test = input('Write findings to database? [Y] Yes [N] No: ')
        answer = sys_test.strip()[0].lower()
        if answer not in ['y', 'n'] or answer == 'n':
            print(f'[!] {answer} not identified as a response')
            raise SystemExit

        if answer == 'y':
            mylist = [
                {'Target_IP': self.target},
                {'Vendor_Name': self.vendor_name},
                {'HTTP_Hash': self.http_hash},
                {'Ports': shodan_results.shodan_request(self.target)},
                {'Resolved_Domains': riskiq_results.request_riskiq(self.target)}
            ]

        db_collection.insert_many(mylist)
        conn_mongo_cli.close()
            

    def run(self):
        self.process_ipaddr(self.target)
        self.process_ipaddr(self.target)
        self.get_vendor_info()
        shodan_results.shodan_request(self.target)
        riskiq_results.request_riskiq(self.target)
        self.connect_database()


def menu():
    print("""
 _______  ___   __    _  ___   _  __   __  _______  ___      _______  ______    _______  ______   _______  ______   
|       ||   | |  |  | ||   | | ||  | |  ||       ||   |    |       ||    _ |  |   _   ||      | |   _   ||    _ |  
|  _____||   | |   |_| ||   |_| ||  |_|  ||   _   ||   |    |    ___||   | ||  |  |_|  ||  _    ||  |_|  ||   | ||  
| |_____ |   | |       ||      _||       ||  | |  ||   |    |   |___ |   |_||_ |       || | |   ||       ||   |_||_ 
|_____  ||   | |  _    ||     |_ |       ||  |_|  ||   |___ |    ___||    __  ||       || |_|   ||       ||    __  |
 _____| ||   | | | |   ||    _  ||   _   ||       ||       ||   |___ |   |  | ||   _   ||       ||   _   ||   |  | |
|_______||___| |_|  |__||___| |_||__| |__||_______||_______||_______||___|  |_||__| |__||______| |__| |__||___|  |_|


SinkholeRadar
----------------------------------------------------------------
DNS Sinkhole monitor inspired by The Vertex Project Blog. 
Identify new sinholed IPs and save information (HTML hash, ports, domains captured, etc.) to a database for further investigation.

Example:
python3 sinkholeradar.py 
    
""")


def main():
    menu()
    target = input('Enter an IP address: ')
    print()
    processor = SinkholeRadar(target)
    processor.run()


if __name__ == "__main__":
    main()

