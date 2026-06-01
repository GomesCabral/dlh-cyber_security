#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

def download_page(url):
	try:
		response = requests.get(url)
		soup = BeautifulSoup(response.txt, 'html.parser')
		return soup.prettify()
	except requests.exceptions.RequestException as e:
		return f"Error Downloading the page: {str(e)}"

if __name__=="__main__":
	import sys

	if len(sys.argv) != 2:
		print("Usage: python3 2-download_page.py <url>")
		sys.exit(1)

	url = sys.argv[1]
	content = download_page(url)
	print(content)
