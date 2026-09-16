from urllib.parse import urlparse, unquote
import ipaddress

SUSPICIOUS_TLDS = { 
	".zip",
	".mov",
	".click",
	".top",
	".xyz",
	".work",
	".gq",
	".tk",
	".ml",
	".ga",
	".cf",
}


def analyze_url(url: str):

	result = {
		"url": url,
		"valid": False,
		"https": False,
		"domain": None,
		"port": None,
		"is_ip": False,
		"suspicious": False,
		"indicators": []
	}

	# Parse URL

	parsed = urlparse(url)

	if parsed.scheme not in ["http", "https"]:
		result["indicators"].append("Invalid or unsupported  URL Scheme")
		return result

	if not parsed.hostname:
		result["indicators"].append("No hostname found")
		return result

	result["valid"] = True
	result["domain"] = parsed.hostname
	result["https"] = parsed.scheme == "https"
	result["port"] = parsed.port

	hostname = parsed.hostname.lower()

	# IP address detection

	try:
		ipaddress.ip_address(hostname)
		result["is_ip"] = True
		result["suspicious"] = True
		result["indicators"].append(
			"URL uses an IP address instead of a domain"
		)
	except ValueError:
		pass

	# HTTPS
	
	if not result ["https"]:
		result["suspicious"] = True
		result["indicators"].append(
			"Connection does not use HTTPS"
		)

	# Suspicious ports
	
	suspicious_ports = {
		21,
		22,
		23,
		25,
		445,
		3389,
		8080,
		8843,
	}

	if result ["port"] in suspicious_ports:
		
		result["suspicious"] = True

		result ["indicators"].append(f"URL uses unusual port {result['port']}")

	# Excessive subdomains

	domain_parts = hostname.split(".")

	if len(domain_parts) >= 5:
		result["suspicious"] = True

		result["indicators"].append("Domain contains an unusually large nummber of subdomains")

	# Punycode

	if "xn--" in hostname:

		result["suspicious"] = True

		result["indicators"].append("Domain uses punycode")

	# Suspicious TLD 

	for tld in SUSPICIOUS_TLDS:

		if hostname.endswith(tld):

			result["suspicious"] = True
			result["indicators"].append(f"Domain uses potentially suspicious TLD {tld}")
	
		break

	# @ character
 
	if "@" in url:
		result["suspicious"] = True
		result["indicators"].append(
			"URL contains @ character")

	# URL encoding 

	decoded_url = unquote(url)

	if decoded_url != url:
		result["suspicious"] = True
		result["indicators"].append("URL contains encoded characters")

	# Long URL

	if len(url) > 200:
		result["suspicious"] = True
		result["indicators"].append(" URL is unusually long")

	# Long hostname

	if len(hostname) > 50:
		result["suspicious"] =  True
		result["indicators"].append("Hostname is unusually long")

	# Hyphen-heavy domain
	
	if hostname.count("-") >=3:
		result["suspicious"] = True
		result["indicators"].append("Domain contains multiple hyphens")

	# Credentials in URL

	if parsed.username or parsed.password:
		result["suspicious"] = True
		result["indicators"].append("URL contains embedded ursername or password")

	# Double slash in path
	
	if "//" in parsed.path:
		result["suspicious"] = True
		result["indicators"].append("URL path contains multiple consecutive slashes")

	return result

	return result


