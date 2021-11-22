from bs4 import BeautifulSoup
from dotenv import load_dotenv
from database_stuff import Example
import requests
import mmh3 
import logging
import os
import shodan 

load_dotenv()

logging.basicConfig(level=logging.DEBUG, filename='sinkholeradarlog.log', format='%(asctime)s %(levelname)s:%(message)s')


class SinkholeRadar:

    def __init__(self, target: str):
        self.target = target
        
    def process_ipaddr(self, target):
        
        print(f'[+] Verifying {target} is a sinkhole...\n')
        prepend_http = 'http://'
        
        self.response = requests.get(prepend_http + target)
           
        self.http_hash = mmh3.hash(self.response.text)

        sinkhole_headers = ['X-Sinkhole', 'Server: X-SinkHole', 'Server: 360Netlab-sinkhole']
        
        if sinkhole_headers in self.response.headers:
            print('[+] Possible sinkhole identified!\n')
            logging.debug(f'{target} contains sinkhole indicators')
            print(f'[+] http.html_hash: {self.http_hash}')
            logging.debug('http_hash written')
            print()
        else:
            print('[!] This may not be a sinkhole. Try a manual search.')
            logging.debug(f'{target} does not match the sinkhole indicators')
            raise SystemExit

    def get_vendor_info(self):
        self.vendor_name = ''
        soup = BeautifulSoup(self.response.text, 'lxml')
        head_tags = 'h1'
        print('[+] Viewing Header Tag to identify vendor: \n')
        for tag in soup.find_all(head_tags):
        
            print(tag.name + ' -> ' + tag.text.strip())
            print()
        find_message = 'Did you find the vendor name?\n[Y] Yes [N] No: '
        print()
        while True:
            user_input = input(find_message)
            user_response = user_input.strip()[0].lower()
            if user_response not in ['y', 'n']:
                print(f'[-] Response {user_response} not identified')
                logging.debug('User response not identified')
                continue
            if user_response == 'n':
                print('Vendor information may be in a different HTML tag, moving on...')
                self.vendor_name = self.vendor_name
                logging.debug('User responded "no"')
                break
            if user_response == 'y':
                print()
                self.vendor_name = str(input('Vendor name: '))
                print(f'[+] Vendor {self.vendor_name} saved !\n')
                logging.debug('vendor name successfully saved')
                break
            print()

    def shodan_request(self):
        shodan_env_key = os.getenv('SHODAN_APIKEY')
        shodan_key = shodan.Shodan(shodan_env_key)
        shodan_results = shodan_key.host(self.target)
        list_ports = []
        print('[+] Open ports: \n')
        try:
            for ports in shodan_results['data']:
                list_ports.append(ports['port'])
                self.open_ports = [x for x in list_ports]

            print()
            print(self.open_ports)
            logging.debug('Open ports saved')
            print()
        except shodan.APIError as err:
            print(err)

    def request_riskiq_api(self):
        url = 'https://api.riskiq.net/pt/v2/dns/passive'
        api_username = os.getenv('RISKIQ_USERNAME')
        api_key = os.getenv('RISKIQ_APIKEY')
        headers = {'User-Agent': 'Threat Research, SinkholeRadar v0.1', 'Content-Type': 'application/json'}
        auth = (api_username, api_key)
        data = {'query': self.target}
        list_domains = []
        print('[+] Resolutions: \n')
        try:
            
            self.riskiq_response = requests.get(url, auth=auth, json=data, headers=headers)
            result_data = self.riskiq_response.json()
            
            for items in result_data['results']:
                list_domains.append(items['resolve'])
                self.sinkholed_domains = [x for x in list_domains]

            print(self.sinkholed_domains)
            logging.debug(f' {len(self.sinkholed_domains)} Captured domains found')
            print()

        except requests.ReadTimeout:
            logging.debug('Exception raised')
            raise(f'[!] Page timed out for {self.target}')
            

        except requests.HTTPError as err:
            logging.debug('Request Error exception raised')
            raise(f'[!] {err}')

    def connect_to_database(self):
        insert_to_db = input('Insert findings to database? [Y] Yes [N] No: ')
        print()
        user_answer = insert_to_db.strip()[0].lower()
        
        if user_answer not in ['y', 'n']:
            print(f'[!] {user_answer} not identified as expected response, exiting...')
            logging.debug('User response not identified')
            raise SystemExit

        if user_answer == 'n':
            print('[-] Not inserting data to database, exiting...')
            logging.debug('User responded "no"')
            raise SystemExit

        if user_answer == 'y':
            self._build_db_document()
            logging.debug('Data for sinkhole IP address written to database')

    def _build_db_document(self):
        mytest = Example()
        mytest.Target_IP = self.target
        mytest.Vendor_name = self.vendor_name
        mytest.Http_Hash = self.http_hash
        mytest.Open_Ports = self.open_ports
        mytest.Domains = self.sinkholed_domains
        mytest.save()
      
    def run(self):
        self.process_ipaddr(self.target)
        self.get_vendor_info()
        self.shodan_request()
        self.request_riskiq_api()
        self.connect_to_database()
        


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

