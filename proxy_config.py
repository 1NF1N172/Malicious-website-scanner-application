# proxy_config.py

import requests
import random
import logging

# логгинг
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# API ключ
api_key = 'rzva1gtogzp2ftthptpzb4vfoffr92bkhgf1hik1'

# креденшлите
proxy_username = 'lfhchccj'      
proxy_password = '9i8ldqafhxgh'  

# басе урл 
base_url = 'https://proxy.webshare.io/api/v2'

# хеадърите с апи ключа
headers = {
    'Authorization': f'Token {api_key}'
}

# фетчване на прксита
def fetch_proxy_list():
    proxies = []
    page = 1
    while True:
        params = {
            'page': page,
            'page_size': 100,
            'mode': 'direct',  
        }
        # тук фи филтрирам по лайбъл
        # label = 'projectx'
        # if label:
        #     params['search'] = label

        response = requests.get(f'{base_url}/proxy/list/', headers=headers, params=params)
        if response.status_code != 200:
            raise Exception(f'Failed to get proxy list from Webshare: {response.status_code} {response.text}')

        data = response.json()
        logger.debug(f"Data received from API: {data}")

        for proxy in data['results']:
            proxy_address = proxy['proxy_address']
            proxy_port = proxy['port']  
            # тук влизат креденшълите в употреба
            proxy_str = f"{proxy_username}:{proxy_password}@{proxy_address}:{proxy_port}"
            proxies.append(proxy_str)

        if not data['next']:
            break
        page += 1

    logger.debug(f"Number of proxies fetched: {len(proxies)}")
    return proxies

proxy_list = fetch_proxy_list()

def get_random_proxy():
    if not proxy_list:
        raise Exception("No proxies available. Check your proxy configuration.")
    proxy = random.choice(proxy_list)
    logger.debug(f"Selected proxy: {proxy}")
    return proxy

def get(url, **kwargs):
    proxy = get_random_proxy()
    proxies = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}',
    }
    logger.debug(f"Using proxy for GET request: {proxies}")
    return requests.get(url, proxies=proxies, **kwargs)

def post(url, **kwargs):
    proxy = get_random_proxy()
    proxies = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}',
    }
    logger.debug(f"Using proxy for POST request: {proxies}")
    return requests.post(url, proxies=proxies, **kwargs)

def request(method, url, **kwargs):
    proxy = get_random_proxy()
    proxies = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}',
    }
    logger.debug(f"Using proxy for {method.upper()} request: {proxies}")
    return requests.request(method, url, proxies=proxies, **kwargs)

def Session():
    """Create a session that uses a proxy."""
    session = requests.Session()
    # избира си прокси
    proxy = get_random_proxy()
    proxies = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}',
    }
    session.proxies.update(proxies)
    logger.debug(f"Session created with proxies: {proxies}")
    return session