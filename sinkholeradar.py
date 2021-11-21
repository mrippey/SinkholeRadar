from bs4 import BeautifulSoup
from dotenv import load_dotenv
from database_stuff import Example
import httpx
import mmh3 
import os
import shodan 

load_dotenv()


class SinkholeRadar:

    def __init__(self, target: str):
        self.target = target
        
    def process_ipaddr(self, target):
        
        print(f'[+] Verifying {target} is a sinkhole...\n')
        prepend_http = 'http://'
        
        with httpx.Client() as client:
            self.response = client.get(prepend_http + target)
           
        self.http_hash = mmh3.hash(self.response.text)
        
        if 'X-Sinkhole' in self.response.headers:
            print('[+] Possible sinkhole identified!\n')
            print(f'[+] http.html_hash: {self.http_hash}')
            print()
        else:
            print('[!] This may not be a sinkhole. Try a manual search.')
            raise SystemExit

    def get_vendor_info(self):
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
                    continue
                if user_response == 'n':
                    print('Vendor information may be in a different HTML tag, moving on...')
                    break
                if user_response == 'y':
                    print()
                    self.vendor_name = str(input('Vendor name: '))
                    print(f'[+] Vendor {self.vendor_name} saved !\n')
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
            with httpx.Client() as client:
                self.riskiq_response = client.get(url, auth=auth, json=data, headers=headers)
            result_data = self.riskiq_response.json()
            
            for items in result_data['results']:
                list_domains.append(items['resolve'])
                self.sinkholed_domains = [x for x in list_domains]

            print(self.sinkholed_domains)
            print()

        except httpx.TimeoutException:
            raise(f'[!] Page timed out for {self.target}')

        except httpx.RequestError as err:
            raise(f'[!] {err}')

    def connect_to_database(self):
        insert_to_db = input('Insert findings to database? [Y] Yes [N] No: ')
        print()
        user_answer = insert_to_db.strip()[0].lower()
        
        if user_answer not in ['y', 'n']:
            print(f'[!] {user_answer} not identified as expected response, exiting...')
            raise SystemExit

        if user_answer == 'n':
            print('[-] Not inserting data to database, exiting...')
            raise SystemExit

        if user_answer == 'y':
            self._build_db_document()

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

