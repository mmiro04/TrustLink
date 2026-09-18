import requests

from backend.scanner.url_security import validate_url_for_request


MAX_REDIRECTS = 5


def analyze_redirects(url: str):

    result = {
        "url": url,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "error": None
    }

    current_url = url

    try:

        for _ in range(MAX_REDIRECTS + 1):

            # Validate the URL before making the request
            allowed, reason = validate_url_for_request(
                current_url
            )

            if not allowed:

                result["error"] = (
                    f"Request blocked: {reason}"
                )

                result["final_url"] = current_url

                return result

            response = requests.get(
                current_url,
                timeout=5,
                allow_redirects=False,
                headers={
                    "User-Agent": "LinkTrust/1.0"
                }
            )

            # Check whether this response is a redirect
            if response.is_redirect:

                location = response.headers.get("Location")

                result["redirect_chain"].append(
                    {
                        "url": current_url,
                        "status_code": response.status_code,
                        "location": location
                    }
                )

                result["redirect_count"] += 1

                if not location:

                    result["error"] = (
                        "Redirect response has no Location header"
                    )

                    result["final_url"] = current_url

                    return result

                # Resolve relative redirects
                from urllib.parse import urljoin

                current_url = urljoin(
                    current_url,
                    location
                )

                continue

            # Final destination reached
            result["final_url"] = response.url

            return result

        result["final_url"] = current_url

        result["error"] = (
            f"Maximum redirect limit of "
            f"{MAX_REDIRECTS} exceeded"
        )

    except requests.RequestException as e:

        result["error"] = str(e)

    return result
