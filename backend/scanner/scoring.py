def calculate_risk(analysis):

	score = 0
	reasons = []

	# HTTPS
	if not analysis["https"]:
		score += 10
		reasons.append("Connectin does not use HTTPS")

	# IP address instead of domain
	if analysis["is_ip"]:
		score += 25
		reasons.append("URL uses an IP address instead of a domain")
		
	# Exisiting suspicious findings
	if analysis ["suspicious"]:
		score += 10
	
	# Specific suspicious indicators
	for reason in analysis["reasons"]:
		if "@" in reason:
			score += 15
	
		if "unusually long" in reason:
			score += 10

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
