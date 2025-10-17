print("hello world")

# GOAL:
# - SQLMap but for the CSRF vulnerability
# - Criteria: Automatically pass all the Burp Suite labs

# TASK:
# - Send a request to endpoint
import argparse
import requests
import json

def parse_cookie_input(cookie_str):
    cookies = {}
    for pair in cookie_str.split(';'):
        if '=' in pair:
            key, value = pair.strip().split('=', 1)
            cookies[key] = value
    return cookies

def parse_data_input(data_str, data_format):
    try:
        if data_format == 'json':
            return json.loads(data_str)
        elif data_format == 'form':
            return dict(pair.split('=') for pair in data_str.split('&'))
    except Exception as e:
        print(f"Error parsing data: {e}")
        return None

def probe_http_methods(url, cookies=None, data=None, data_format='json'):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    results = {}

    for method in methods:
        try:
            kwargs = {'cookies': cookies}
            if method in ['POST', 'PUT', 'PATCH']:
                if data_format == 'json':
                    kwargs['json'] = data
                elif data_format == 'form':
                    kwargs['data'] = data

            response = requests.request(method, url, **kwargs)
            results[method] = {
                'status_code': response.status_code,
                'reason': response.reason,
                'allowed': True
            }
        except requests.exceptions.RequestException as e:
            results[method] = {
                'error': str(e),
                'allowed': False
            }

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe HTTP methods on a given endpoint.")
    parser.add_argument("url", help="Target URL to probe")
    parser.add_argument("--cookies", help="Cookies in 'key=value; key2=value2' format", default="")
    parser.add_argument("--data", help="Request body data (JSON or URL-encoded)", default="")
    parser.add_argument("--format", choices=["json", "form"], default="json", help="Data format: 'json' or 'form'")

    args = parser.parse_args()

    cookies = parse_cookie_input(args.cookies) if args.cookies else None
    data = parse_data_input(args.data, args.format) if args.data else None

    results = probe_http_methods(args.url, cookies, data, args.format)

    print("\nHTTP Method Probe Results:")
    for method, info in results.items():
        if info.get('allowed'):
            print(f"{method}: {info['status_code']} {info['reason']}")
        else:
            print(f"{method}: Not allowed or failed - {info['error']}")

