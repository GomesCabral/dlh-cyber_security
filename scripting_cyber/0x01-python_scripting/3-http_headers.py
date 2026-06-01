#!/bin/env python3
import requests

def get_http_headers(url):
	my_dict = {}

	try:
		response = requests.get(url)
		return {
			'status_code': response.status_code,
			'headers': dict(response.headers)
		}
	except requests.exceptions.RequestException as e:
		return None

if __name__=="__main__":
	import sys

	if len(sys.argv) != 2:
		print("Usage: python3 3-main.py <url>")
		sys.exit(1)

url = sys.argv[1]

result = get_http_headers(url)

if result is None:
	print(f"Error: Could not retrieve headers from {url}")
	sys.exit(1)

print(f"HTTP Headers for: {url}")
print("=" * 50)
print(f"Status Code: {result['status_code']}")
print("Headers:")
print()

for key, value in result['headers'].items():
	print(f"  {key}: {value}")
