from urllib.parse import urlparse
import ipaddress

def analyze_url(url: str):

	result = {
		"url": url,
		"valid": False,
		"https": False,
		"domain": None,
		"is_ip": False,
		"suspicious": False,
		"reasons": []
	}

	parsed = urlparse(url)

	if parsed.scheme not in ["http", "https"]:
		result["reasons"].append("Invalid URL Scheme")
		return result

	if not parsed.hostname:
		result["reasons"].append("No hostname found")
		return result

	result["valid"] = True
	result["domain"] = parsed.hostname
	result["https"] = parsed.scheme == "https"

	try:
		ipaddress.ip_address(parsed.hostname)
		result["is_ip"] = True
		result["suspicious"] = True
		result["reasons"].append(
			"URL uses an IP address instead of a domain"
		)
	except ValueError:
		pass

	if len(url) > 200:
		result["suspicious"] = True
		result["reasons"].append(
			"URL is unusually long"
		)

	if "@" in url:
		result["suspicious"] = True
		result["reasons"].append(
			"URL contains @ character"
		)

	return result


