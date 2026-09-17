import requests

def analyze_redirects(url: str):

	result = { 
		"url": url,
		"final_url": None,
		"redirect_count": 0,
		"redirect_chain": [],
		"error": None
	}

	try: 
		response = requests.get(
			url,
			timeout=5,
			allow_redirects=True,
			headers={
				"User-Agent": "LinkTrust/1.0"
			}
		)

		result["final_url"] = response.url

		result["redirect_count"] = len(
			response.history
		)

		result["redirect_chain"] = [
			{
				"url": redirect.url,
				"status_code": redirect.status_code,
				"location": redirect.headers.get("Location")
			}
			for redirect in response.history
		]

	except requests.RequestException as e:
		result["error"] = str(e)
	
	return result
