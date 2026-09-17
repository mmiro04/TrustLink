def calculate_risk(analysis, dns=None, ssl_info=None, redirects=None):

	score = 0
	reasons = []

	indicators = analysis["indicators"]

	# score individual indicators
	
	for indicator in indicators:

		if "IP address" in indicator:
			score += 25
		elif "HTTPS" in indicator:
			score += 10
		elif "suspicious TLD" in indicator:
			score += 15
		elif "Punycode" in indicator:
			score += 20
		elif "@ character" in indicator:
			score += 20
		elif "encoded characters" in indicator:
			score += 10
		elif "unusually long" in indicator:
			score += 10
		elif "unusually  large nummber of subdomains" in indicator:
			score += 15
		elif "multiple hyphens" in indicator:
			score += 10
		elif "embeded username oor password" in indicator:
			score += 20
		elif "unusual port" in indicator:
			score += 10
		elif "consecutive slashes" in indicator:
			score += 5
		else:
			score +=5 

		reasons.append(indicator)

	#DNS analysis
	
	if dns:
		if dns["errors"]:
			score += 10

			resons.append(
				"DNS analysis encountered an error"
			)
		if not dns["a"] and not dns["aaaa"]:
			score += 20
			reasons.append("Domain has no A or AAAA DNS records")

	#SSL/TLS analysis
	
	if analysis["https"]:
		if ssl_info:
			if ssl_info["error"]:
				score += 20

				reasons.append("SSL/TLS connection could not be verified")
			elif ssl_info["days_until_expiry"] is not None:
				if ssl_info["days_until_expiry"] < 0:
					score += 30

					reasons.append("SSL/TLS Certificate has expired")
				elif ssl_info["days_until_expiry"] <=30:
					score += 10
				
					reasons.append("SSL/TLS certificate expires within 30 days") 

	# Redirect analysis
	if redirects:

		if redirects["redirect_count"] >=3:
			score +=15

			reasons.append("URL ures multiple redirects")
		if redirects["final_url"]:
			original_url = analysis["url"].rstrip("/")
			final_url = redirects["final_url"].rstrip("/")

			if final_url.lower() != original_url.lower():
				score += 5

				reasons.append("URL redirects to a different final destination")
	
	
	# Prevent score from exceeding 100
	score = min(score, 100)


	# Determine risk level
	if score <= 20:
		level = "Low Risk"
	elif score <= 50:
		level = "Suspicious"	
	elif score <= 75:
		level = "High Risk"
	else: 
		level = "Dangerous"

	return {
		"score" : score,
		"level" : level,
		"reasons" : reasons
	}
