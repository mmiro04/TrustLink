def calculate_risk(analysis):

	score = 0
	reasons = []

	indicators = analysis["indicators"]

	# score individual indicators
	
	for indicator in indicators:

		if "IP address" in indicator:
			score += 25
		elif "HTTPS" in indicator:
			scoore += 10
		elif "suspicious TLD" in indicator:
			score += 15
		elif "Punycode" in indiicator:
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
