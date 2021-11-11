from dotenv import load_dotenv
 import os
 import requests 


 load_dotenv()

 def request_riskiq(target: str):
     url = 'https://api.riskiq.net/pt/v2/dns/passive'
     api_username = os.getenv('RISKIQ_USERNAME')
     api_key = os.getenv('RISKIQ_APIKEY')
     headers = {'User-Agent': 'Threat Research, SinkholeRadar v0.1'}
     auth = (api_username, api_key)
     data = {'query': target}

     try:
         response = requests.get(url, auth=auth, json=data, headers=headers)
         return response.json()
     except requests.exceptions.ConnectionError as err:
        print(f'[!] {err}')


#TODO Fix this function to work with main class
def fetch_data():
    sinkholed_domains = []
    results = request_riskiq(target=target)
    print(f'[+] Sinkholed domains for: {target}\n')

    for items in request_riskiq['results']:
        sinkholed_domains.append(items['resolve'])
        
        print(f"[+] Resolution: {','.join(map(str, sinkholed_domains))}")

        if sinkholed_domains is None:
            print('[-] No resolutions were found!')
