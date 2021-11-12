from dotenv import load_dotenv
import os
import requests 


load_dotenv()

def request_riskiq(target: str):
    sinkholed_domains = []
    url = 'https://api.riskiq.net/pt/v2/dns/passive'
    api_username = os.getenv('RISKIQ_USERNAME')
    api_key = os.getenv('RISKIQ_APIKEY')
    headers = {'User-Agent': 'Threat Research, SinkholeRadar v0.1', 'Content-Type': 'application/json'}
    auth = (api_username, api_key)
    data = {'query': target}

    try:
       response = requests.get(url, auth=auth, json=data, headers=headers)
       result_data = response.json()

	for items in result_data['results']:
            sinkholed_domains.append(items['resolve'][:10]
          
	 print(f'[+] Resolution: {",".join(map(str, sinkholed_domains))}')

    except requests.exceptions.Timeout:
        raise(f'[!] Page timed out for {target}')

    except requests.RequestException as err:
        raise(f'[!] {err}')
     
