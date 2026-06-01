#!/usr/bin/env python3
import socket

def resolve_domain_to_ipv4(domain_name):
	try:
		ip_address = socket.gethostbyname(domain_name)
		return ip_address
	except socket.gaierror:
		return None
	except Exception as e:
		return str(e)

if __name__ == "__main__":
	test_domains = [
		"holbertonschool.com",
        	"google.com",
        	"github.com",
        	"example.com",
        	"this-is-not-a-site.com",
	]

	print("DNS Resolver Test")
	print("=" * 60)

	for domain in test_domains:
		result = resolve_domain_to_ipv4(domain)
		if result:
			print(f"{domain:40} -> {result}")
		else:
			print(f"{domain:40} -> Failed to resolve")

	print("=" * 60)
