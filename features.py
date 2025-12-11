# features.py

import re
import requests
from urllib.parse import urlparse
import socket
import ssl
import whois
from datetime import datetime
from dateutil import parser as date_parser  # За гъвкав анализ на дати
import time
import logging
import math
from collections import Counter
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def resolve_ip(url):
    """Resolve IP address from URL."""
    try:
        parsed_url = urlparse(url)
        ip = socket.gethostbyname(parsed_url.netloc)
        return 1, ip
    except socket.gaierror:
        logger.error(f"Error resolving IP for URL {url}")
        return 0, None

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 1 if len(url) >= 54 else 0

def get_depth(url):
    return len([i for i in urlparse(url).path.split('/') if i])

def redirection(url):
    return 1 if url.count('//') > 1 else 0

def http_domain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tiny_url(url):
    return 1 if re.search(shortening_services, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        response = requests.head(url, timeout=10)
        content_length = response.headers.get('Content-Length')
        return 1 if content_length and int(content_length) < 100000 else 0
    except Exception as e:
        logger.error(f"Error fetching web traffic data for {url}: {e}")
        return 0

def domain_age(domain_info):
    try:
        creation_date = parse_date(domain_info.creation_date)
        if not creation_date:
            return 1  # Посочете потенциално злонамерен, ако липсва датата на създаване
        age_of_domain = (datetime.now() - creation_date).days
        return 1 if (age_of_domain / 30) < 6 else 0
    except Exception as e:
        logger.error(f"Error calculating domain age: {e}")
        return 0

def domain_end(domain_info):
    try:
        expiration_date = parse_date(domain_info.expiration_date)
        if not expiration_date:
            return 1  # Посочете потенциално злонамерен, ако липсва срок на годност
        end = (expiration_date - datetime.now()).days
        return 1 if (end / 30) < 6 else 0
    except Exception as e:
        logger.error(f"Error calculating domain end: {e}")
        return 0

def get_registrar_data(domain_info):
    try:
        registrar = domain_info.registrar  
        return registrar if registrar else "N/A"
    except Exception as e:
        logger.error(f"Error fetching registrar data: {e}")
        return "N/A"

def extract_emails(content):
    return re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)

def check_ssl_expiry(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return 1 if not_after > datetime.now() else 0
    except Exception as e:
        logger.error(f"Error checking SSL expiry: {e}")
        return 0

def iframe(response):
    return 0 if re.findall(r"<iframe|<frameBorder>", response.text) else 1

def mouse_over(response):
    return 1 if re.findall(r"<script>.+onmouseover.+</script>", response.text) else 0

def right_click(response):
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

def forwarding(response):
    return 1 if len(response.history) > 2 else 0

def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomain = entry['name_value']
                subdomains.update([sd.strip() for sd in subdomain.split('\n') if sd.strip()])
            return list(subdomains)
        else:
            logger.error(f"Failed to fetch subdomains for {domain}. Status code: {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Error fetching subdomains for {domain}: {e}")
        return []

def calculate_entropy(url):
    p, lns = Counter(url), float(len(url))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def parse_date(date_input):
    """Parse date from various formats to datetime object."""
    if not date_input:
        return None
    if isinstance(date_input, list):
        date_input = date_input[0]
    if isinstance(date_input, datetime):
        return date_input
    if isinstance(date_input, str):
        try:
            return date_parser.parse(date_input)
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing date '{date_input}': {e}")
            return None
    return None

def google_index(url):
    """Check if the URL is indexed by Google."""
    try:
        query = f"site:{url}" #Заобикаляне чрез Site: оператор, да не се използва Google Search API. Недостиг, е при много използване може да се забрани адреса, но за тази цел всекa заявка минава през различно proxy
        search_url = f"https://www.google.com/search?q={query}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(search_url, headers=headers, timeout=10)
        if "did not match any documents" in response.text:
            return 0  # Not indexed
        return 1  # Indexed
    except Exception as e:
        logger.error(f"Error checking Google index for {url}: {e}")
        return 0  # Default to not indexed on error

def feature_extraction(url, expected_feature_count, return_all=False):
    features = []
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        raise ValueError("Please provide a full URL including scheme (http:// or https://)")

    ip_flag, ip = resolve_ip(url)
    features.append(ip_flag)
    features.append(have_at_sign(url))
    features.append(get_length(url))

    indexed = google_index(url)
    features.append(indexed)

    hostname = parsed_url.hostname or ""
    features.append(len(hostname))

    entropy_value = calculate_entropy(url)
    features.append(entropy_value)

    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('?'))
    features.append(url.count('&'))
    features.append(url.count('|'))
    features.append(url.count('='))
    features.append(url.count('_'))
    features.append(url.count('~'))
    features.append(url.count('%'))
    features.append(url.count('/'))
    features.append(url.count('*'))
    features.append(url.count(':'))
    features.append(url.count(','))
    features.append(url.count(';'))
    features.append(url.count('$'))
    features.append(url.count(' '))
    features.append(url.count('www.'))
    features.append(url.count('.com'))
    features.append(url.count('//'))
    features.append(1 if 'http' in url else 0)
    features.append(1 if 'https' in url else 0)
    features.append(len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0)
    features.append(len(re.findall(r'\d', hostname)) / len(hostname) if len(hostname) > 0 else 0)
    features.append(1 if re.search(r'xn--', hostname) else 0)
    features.append(parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443))

    try:
        domain_info = whois.whois(parsed_url.netloc)
        features.append(1)  # WHOIS successful
        registrar = get_registrar_data(domain_info)  
    except Exception as e:
        logger.error(f"Error fetching WHOIS data: {e}")
        domain_info = None
        features.append(0)  
        registrar = "No information provided"

    registrar_encoded = 0 if registrar == "No information provided" else 1
    features.append(registrar_encoded)
    features.append(web_traffic(url))
    features.append(domain_age(domain_info) if domain_info else 1)
    features.append(domain_end(domain_info) if domain_info else 1)

    try:
        response = requests.get(url, timeout=10)
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
        emails = extract_emails(response.text)
        features.append(len(emails))
    except requests.exceptions.Timeout:
        logger.error(f"Timeout error fetching content from {url}")
        features.extend([1, 1, 1, 1, 0])  # Default values in case of timeout
    except Exception as e:
        logger.error(f"Error fetching content from {url}: {e}")
        features.extend([1, 1, 1, 1, 0])  # Default values in case of error

    subdomains = get_subdomains(parsed_url.netloc)
    features.append(len(subdomains))
    ssl_valid = check_ssl_expiry(url)
    features.append(1 if ssl_valid else 0)
    logger.debug(f"Extracted features: {features}")

    location_info = {}

    if len(features) < expected_feature_count:
        features.extend([0] * (expected_feature_count - len(features)))
    elif len(features) > expected_feature_count:
        features = features[:expected_feature_count]

    # Return values based on return_all flag
    if return_all:
        return features, ip, location_info, ssl_valid, {}, 0
    return features

def get_whois_info(url):
    info = {}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  #махане на порта ако е на лице
        domain_name = whois.whois(domain)
        logger.debug(f"WHOIS raw data for {domain}: {domain_name}")

        creation_date = parse_date(domain_name.creation_date)
        expiration_date = parse_date(domain_name.expiration_date)
        updated_date = parse_date(domain_name.updated_date)

        info["creation_date"] = creation_date.strftime('%Y-%m-%d') if creation_date else "No information provided"
        info["expiration_date"] = expiration_date.strftime('%Y-%m-%d') if expiration_date else "No information provided"
        info["updated_date"] = updated_date.strftime('%Y-%m-%d') if updated_date else "No information provided"

        nameservers = domain_name.name_servers
        if nameservers:
            if isinstance(nameservers, str):
                nameservers = [nameservers]
            info["name_servers"] = ', '.join(nameservers)
        else:
            info["name_servers"] = "No information provided"

        contact_email = domain_name.emails
        if contact_email:
            if isinstance(contact_email, str):
                contact_email = [contact_email]
            info["contact_email"] = ', '.join(contact_email)
        else:
            info["contact_email"] = "No information provided"

        registrar = domain_name.registrar
        info["registrar"] = registrar if registrar else "No information provided"

        if creation_date:
            age_of_domain = (datetime.now() - creation_date).days
            info["age_of_domain_days"] = age_of_domain
        else:
            info["age_of_domain_days"] = "No information provided"

        if expiration_date:
            days_until_expiration = (expiration_date - datetime.now()).days
            info["days_until_expiration"] = days_until_expiration
        else:
            info["days_until_expiration"] = "No information provided"

    except Exception as e:
        logger.exception(f"Error fetching WHOIS info for {url}: {e}")
        info = {
            "creation_date": "No information provided",
            "expiration_date": "No information provided",
            "updated_date": "No information provided",
            "name_servers": "No information provided",
            "contact_email": "No information provided",
            "registrar": "No information provided",
            "age_of_domain_days": "No information provided",
            "days_until_expiration": "No information provided",
        }
    return info
