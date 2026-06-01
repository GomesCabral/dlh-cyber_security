#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(start_url, max_depth=2, visited=None):

	if visited is None:
		visited = set()

	if max_depth < 0 or start_url in visited:
		return visited

	base_domain = urlparse(start_url).netloc

	try:
		print(f"Crawling: {start_url}")
		response = requests.get(start_url, timeout=5)
		visited.add(start_url)

		soup = BeautifulSoup(response.text, 'html.parser')

		for tag in soup.find_all('a', href=True):
			full_url = urljoin(start_url, tag['href'])

		if urlparse(full_url).netloc == base_domain:
			if full_url not in visited:
				crawl_website(full_url, max_depth - 1, visited)
	except Exception:
		pass
	return visited

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 4-web_crawler.py <url> [max_depth]")
        sys.exit(1)

    start_url = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) == 3 else 2
    visited = crawl_website(start_url, max_depth)

    print("\nTotal pages crawled:", len(visited))
