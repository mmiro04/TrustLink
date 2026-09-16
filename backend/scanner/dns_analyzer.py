import dns.resolver

def analyze_dns(domain: str):

	result = {
		"domain": domain,
		"a": [],
		"aaaa": [],
		"cname": [],
		"mx": [],
		"ns": [],
		"errors": []
	}
	
	record_types = {
		"a": "A",
		"aaaa": "AAAA",
		"cname": "CNAME",
		"mx": "MX",
		"ns": "NS"
	}

	for key, record_type in record_types.items():
	
		try:
			answers = dns.resolver.resolve(domain, record_type)

			for answer in answers:
				result[key].append(str(answer))

		except dns.resolver.NoAnswer:
			pass

		except dns.resolver.NXDOMAIN:
			result["errors"].append("Domain does not exist")
			break

		except dns.resolver.NoNameservers:
			result["errors"].append(f"No nameservers available for {record_type} lookup")

		except dns.exception.DNSException as e:
			result["errors"].append(f"{record_type} lookup failed: {str(e)}")

	return result
