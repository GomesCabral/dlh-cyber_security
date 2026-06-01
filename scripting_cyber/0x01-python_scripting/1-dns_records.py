#!/usr/bin/env python3
import dns.resolver

def query_dns_records(domain_name):
	results = {}
	records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

	for type in records:
		try:
			answer = dns.resolver.resolve(domain_name, type)
			results[type] = answer
		except(dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
			pass
	return results

if __name__ == "__main__":
    import sys
    domain_name = sys.argv[1]
    results = query_dns_records(domain_name)
    for record_type, response_text in results.items():
        print(f"\n{record_type} Records:")
        print(response_text.response.to_text())
    print("\nResults dictionary:", results)
