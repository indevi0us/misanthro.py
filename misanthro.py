import requests
import argparse
import threading
import random
import string
import os
import datetime

ASCII_ART = """
\033[91m
 .S_SsS_S.    .S    sSSs   .S_SSSs     .S_sSSs    sdSS_SSSSSSbs   .S    S.    .S_sSSs      sSSs_sSSs           .S_sSSs     .S S.   
.SS~S*S~SS.  .SS   d%%SP  .SS~SSSSS   .SS~YS%%b   YSSS~S%SSSSSP  .SS    SS.  .SS~YS%%b    d%%SP~YS%%b         .SS~YS%%b   .SS SS.  
S%S `Y' S%S  S%S  d%S'    S%S   SSSS  S%S   `S%b       S%S       S%S    S%S  S%S   `S%b  d%S'     `S%b        S%S   `S%b  S%S S%S  
S%S     S%S  S%S  S%|     S%S    S%S  S%S    S%S       S%S       S%S    S%S  S%S    S%S  S%S       S%S        S%S    S%S  S%S S%S  
S%S     S%S  S&S  S&S     S%S SSSS%S  S%S    S&S       S&S       S%S SSSS%S  S%S    d*S  S&S       S&S        S%S    d*S  S%S S%S  
S&S     S&S  S&S  Y&Ss    S&S  SSS%S  S&S    S&S       S&S       S&S  SSS&S  S&S   .S*S  S&S       S&S        S&S   .S*S   SS SS   
S&S     S&S  S&S  `S&&S   S&S    S&S  S&S    S&S       S&S       S&S    S&S  S&S_sdSSS   S&S       S&S        S&S_sdSSS     S S    
S&S     S&S  S&S    `S*S  S&S    S&S  S&S    S&S       S&S       S&S    S&S  S&S~YSY%b   S&S       S&S        S&S~YSSY      SSS    
S*S     S*S  S*S     l*S  S*S    S*S  S*S    S*S       S*S       S*S    S*S  S*S   `S%b  S*b       d*S        S*S           S*S    
S*S     S*S  S*S    .S*P  S*S    S*S  S*S    S*S       S*S       S*S    S*S  S*S    S%S  S*S.     .S*S        S*S           S*S    
S*S     S*S  S*S  sSS*S   S*S    S*S  S*S    S*S       S*S       S*S    S*S  S*S    S&S   SSSbs_sdSSS         S*S           S*S    
SSS     S*S  S*S  YSS'    SSS    S*S  S*S    SSS       S*S       SSS    S*S  S*S    SSS    YSSP~YSSY     SS   S*S           S*S    
        SP   SP                  SP   SP               SP               SP   SP                         S%%S  SP            SP     
        Y    Y                   Y    Y                Y                Y    Y                           SS   Y             Y      
\033[0m
"""
DESCRIPTION = """
Attacking indiscriminately every \033[91mheader\033[0m, \033[91mcookie\033[0m, \033[91mGET\033[0m and \033[91mPOST parameter\033[0m with \033[91mblind fury\033[0m.
Made with \033[91mHATE\033[0m by \033[91mindevi0us\033[0m.
"""

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    END = '\033[0m'

# Load payloads from file
# Load payloads from file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Load URLs from file
def load_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Dynamic payload injection
def inject_dynamic_payload(payload):
    return payload.replace('INJECT_HERE', ''.join(random.choices(string.ascii_letters + string.digits, k=8)))

# Log requests and responses
def log_request_response(url, request, response):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('misanthro_log.txt', 'a') as log_file:
        log_file.write(f"[{timestamp}] Request sent to {url}:\n")
        log_file.write(f"{request.method} {request.url}\n")
        for header, value in request.headers.items():
            log_file.write(f"{header}: {value}\n")
        if request.body:
            log_file.write(f"\n{request.body}\n")
        log_file.write(f"\n[{timestamp}] Response received from {url}:\n")
        log_file.write(f"Status Code: {response.status_code}\n")
        for header, value in response.headers.items():
            log_file.write(f"{header}: {value}\n")
        log_file.write(f"\n{response.text}\n\n")

# Function to get default cookies from the target URL
def get_default_cookies(url):
    try:
        response = requests.get(url)
        return response.cookies.get_dict()
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[!]{Colors.END} Error obtaining default cookies from {Colors.RED}{url}{Colors.END}: {e}")
        return {}

# Function to sanitize headers by replacing INJECT_HERE with a default User-Agent or removing it
def sanitize_headers(headers):
    """Replace INJECT_HERE in headers with a default User-Agent or remove if necessary."""
    default_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    return {key: (default_user_agent if key == 'User-Agent' and value == 'INJECT_HERE' else value) for key, value in headers.items()}

# Function to sanitize cookies by replacing INJECT_HERE with default values or removing it
def sanitize_cookies(cookies, default_cookies):
    """Replace INJECT_HERE in cookies with default values from initial GET request or keep the defaults if not targetted."""
    sanitized_cookies = {}
    for key, value in cookies.items():
        if value == 'INJECT_HERE':
            if key in default_cookies:
                sanitized_cookies[key] = default_cookies[key]
            else:
                sanitized_cookies[key] = ''
        else:
            sanitized_cookies[key] = value
    # Add any default cookies that were not originally in cookies
    for key, value in default_cookies.items():
        if key not in sanitized_cookies:
            sanitized_cookies[key] = value
    return sanitized_cookies

# Function to test payloads against a target
def test_payloads(url, payloads, headers, params, cookies, method, verbose):
    # Get default cookies from an initial GET request to the target URL
    default_cookies = get_default_cookies(url)
    
    # Save default values for headers
    default_headers = {key: value for key, value in headers.items()}

    for payload in payloads:
        dynamic_payload = inject_dynamic_payload(payload)

        # Test for GET parameters
        if method == 'GET' and params:
            for param in params:
                target_params = {key: (dynamic_payload if key == param else value) for key, value in params.items()}
                sanitized_headers = sanitize_headers(default_headers)
                sanitized_cookies = sanitize_cookies(cookies, default_cookies)
                try:
                    response = requests.get(url, headers=sanitized_headers, params=target_params, cookies=sanitized_cookies)
                    if verbose:
                        print(f"{Colors.GREEN}[+]{Colors.END} Injected {dynamic_payload} into {Colors.GREEN}{param}{Colors.END} against {Colors.GREEN}{url}{Colors.END}.")
                    log_request_response(url, response.request, response)
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.RED}[!]{Colors.END} Error attacking {Colors.RED}{url}{Colors.END}: {e}")

        # Test for POST parameters
        elif method == 'POST' and params:
            for param in params:
                target_params = {key: (dynamic_payload if key == param else value) for key, value in params.items()}
                sanitized_headers = sanitize_headers(default_headers)
                sanitized_cookies = sanitize_cookies(cookies, default_cookies)
                try:
                    response = requests.post(url, headers=sanitized_headers, data=target_params, cookies=sanitized_cookies)
                    if verbose:
                        print(f"{Colors.GREEN}[+]{Colors.END} Injected {dynamic_payload} into {Colors.GREEN}{param}{Colors.END} against {Colors.GREEN}{url}{Colors.END}.")
                    log_request_response(url, response.request, response)
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.RED}[!]{Colors.END} Error attacking {Colors.RED}{url}{Colors.END}: {e}")

        # Test for HTTP headers
        for header in headers:
            if headers[header] == 'INJECT_HERE':
                headers_copy = {key: (dynamic_payload if key == header else default_headers[key]) for key in default_headers}
                sanitized_headers = sanitize_headers(headers_copy)
                sanitized_cookies = sanitize_cookies(cookies, default_cookies)
                try:
                    response = requests.get(url, headers=sanitized_headers, cookies=sanitized_cookies) if method == 'GET' else requests.post(url, headers=sanitized_headers, cookies=sanitized_cookies)
                    if verbose:
                        print(f"{Colors.GREEN}[+]{Colors.END} Injected {dynamic_payload} into {Colors.GREEN}{header}{Colors.END} against {Colors.GREEN}{url}{Colors.END}.")
                    log_request_response(url, response.request, response)
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.RED}[!]{Colors.END} Error attacking {Colors.RED}{url}{Colors.END} with header {Colors.RED}{header}{Colors.END}: {e}")

        # Test for cookies
        for cookie in cookies:
            if cookies[cookie] == 'INJECT_HERE':
                cookies_copy = {key: (dynamic_payload + ';' if key == cookie and not dynamic_payload.endswith(';') else dynamic_payload if key == cookie else default_cookies.get(key, '')) for key in cookies}
                sanitized_headers = sanitize_headers(default_headers)
                sanitized_cookies = sanitize_cookies(cookies_copy, default_cookies)
                try:
                    response = requests.get(url, headers=sanitized_headers, cookies=sanitized_cookies) if method == 'GET' else requests.post(url, headers=sanitized_headers, cookies=sanitized_cookies)
                    if verbose:
                        print(f"{Colors.GREEN}[+]{Colors.END} Injected {dynamic_payload} into {Colors.GREEN}{cookie}{Colors.END} against {Colors.GREEN}{url}{Colors.END}.")
                    log_request_response(url, response.request, response)
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.RED}[!]{Colors.END} Error attacking {Colors.RED}{url}{Colors.END} with cookie {Colors.RED}{cookie}{Colors.END}: {e}")

# Threaded function for GET parameter testing
def thread_get(url, payloads, params, headers, cookies, verbose):
    test_payloads(url, payloads, headers, params, cookies, 'GET', verbose)

# Threaded function for POST parameter testing
def thread_post(url, payloads, params, headers, cookies, verbose):
    test_payloads(url, payloads, headers, params, cookies, 'POST', verbose)

# Main function
def main():
    print(ASCII_ART)
    print(DESCRIPTION)

    parser = argparse.ArgumentParser(description='Misanthro.py: The Ultimate Blind Injection Testing Tool')
    parser.add_argument('--url', help='Target URL(s) (comma-separated) or path to a file containing URLs')
    parser.add_argument('--url-file', help='Path to a file containing target URLs')
    parser.add_argument('--payloads', required=True, help='Path to the file containing injection payloads')
    parser.add_argument('--hate-get', help='GET parameters to test, separated by commas')
    parser.add_argument('--hate-post', help='POST parameters to test, separated by commas')
    parser.add_argument('--hate-http-header', help='HTTP headers to test, separated by commas')
    parser.add_argument('--hate-cookie', help='Cookies to test, separated by commas')
    parser.add_argument('--cookie', help='Authenticated cookies')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (-v for basic, -vv for detailed)')

    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    headers = {}
    cookies = {}

    if args.cookie:
        cookies = {cookie.split('=')[0]: cookie.split('=')[1] for cookie in args.cookie.split(';')}

    if args.hate_http_header:
        for header in args.hate_http_header.split(','):
            headers[header.strip()] = 'INJECT_HERE'

    if args.hate_cookie:
        for cookie in args.hate_cookie.split(','):
            cookies[cookie.strip()] = 'INJECT_HERE'

    if args.url_file:
        urls = load_urls(args.url_file)
    elif args.url:
        urls = [url.strip() for url in args.url.split(',') if url.strip()]

    if args.verbose > 0:
        print(f"{Colors.GREEN}[i]{Colors.END} Attacking the following target(s): {', '.join(urls)}")

    threads = []

    for url in urls:
        if args.hate_get:
            get_params = {param.strip(): '' for param in args.hate_get.split(',')}
            t = threading.Thread(target=thread_get, args=(url, payloads, get_params, headers, cookies, args.verbose > 1))
            threads.append(t)
            t.start()

        if args.hate_post:
            post_params = {param.strip(): '' for param in args.hate_post.split(',')}
            t = threading.Thread(target=thread_post, args=(url, payloads, post_params, headers, cookies, args.verbose > 1))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

if __name__ == '__main__':
    main()

