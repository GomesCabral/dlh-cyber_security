#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(start_url, max_depth=2):

	visited = set()

	def _crawl(url, depth):
		if depth < 0 or url in visited:
			return
		base_domain = urlparse(start_url).netloc

		try:
			print(f"Crawling: {url}")
			response = requests.get(url, timeout=5)
			visited.add(url)

			soup = BeautifulSoup(response.text, 'html.parser')

			for tag in soup.find_all('a', href=True):
				full_url = urljoin(url, tag['href'])

				if urlparse(full_url).netloc == base_domain:
					if full_url not in visited:
						_crawl(full_url, max_depth - 1, visited)
		except Exception:
			pass
	_crawl(start_url, max_depth)
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
