from dotenv import load_dotenv
import os
import shodan

load_dotenv()


def shodan_request(target):
    open_instance = []
    shodan_env_key = os.getenv('SHODAN_APIKEY')
    shodan_key = shodan.Shodan(shodan_env_key)

    try:
        shodan_results = shodan_key.host(target)
        
        for r in shodan_results['data']:
            open_instance.append(r['port'])

        print(f"[+] Open ports: {','.join(map(str, open_instance))}")
        
    except shodan.APIError as err:
        print(f'[!] {err}')
