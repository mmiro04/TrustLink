from urllib.parse import urlparse


def calculate_risk(
        analysis,
        dns=None,
        ssl_info=None,
        redirects=None,
        threat_intel=None
):

        score = 0
        reasons = []

        indicators = analysis["indicators"]

        # Score individual indicators

        for indicator in indicators:

                if "IP address" in indicator:
                        score += 25
                elif "does not use HTTPS" in indicator:
                        score += 10
                elif "suspicious TLD" in indicator:
                        score += 15
                elif "punycode" in indicator.lower():
                        score += 20
                elif "@ character" in indicator:
                        score += 20
                elif "encoded characters" in indicator:
                        score += 10
                elif "unusually long" in indicator:
                        score += 10
                elif "unusually large number of subdomains" in indicator:
                        score += 15
                elif "multiple hyphens" in indicator:
                        score += 10
                elif "embedded username or password" in indicator:
                        score += 20
                elif "unusual port" in indicator:
                        score += 10
                elif "consecutive slashes" in indicator:
                        score += 5
                else:
                        score += 5

                reasons.append(indicator)

        # DNS analysis

        if dns:

                if dns["errors"]:

                        reasons.append(
                                "DNS analysis encountered an error"
                        )

                if (
                        not dns["errors"]
                        and not dns["a"]
                        and not dns["aaaa"]
                ):

                        score += 20

                        reasons.append(
                                "Domain has no A or AAAA DNS records"
                        )

        # SSL/TLS analysis

        if analysis["https"]:

                if ssl_info:

                        if ssl_info["error"]:

                                reasons.append(
                                        "SSL/TLS connection could not be verified"
                                )

                        elif ssl_info["days_until_expiry"] is not None:

                                if ssl_info["days_until_expiry"] < 0:

                                        score += 30

                                        reasons.append(
                                                "SSL/TLS Certificate has expired"
                                        )

                                elif ssl_info["days_until_expiry"] <= 30:

                                        score += 10

                                        reasons.append(
                                                "SSL/TLS certificate expires within 30 days"
                                        )

        # Redirect analysis

        if redirects:

                if redirects["redirect_count"] >= 3:

                        score += 15

                        reasons.append(
                                "URL uses multiple redirects"
                        )

                if redirects["final_url"]:

                        original_host = urlparse(
                                analysis["url"]
                        ).hostname

                        final_host = urlparse(
                                redirects["final_url"]
                        ).hostname

                        if (
                                original_host
                                and final_host
                                and original_host.lower()
                                != final_host.lower()
                        ):

                                score += 5

                                reasons.append(
                                        "URL redirects to a different domain"
                                )

        # Threat intelligence

        if threat_intel:

                if threat_intel["error"]:

                        reasons.append(
                                "Threat intelligence check could not be completed"
                        )

                elif threat_intel["available"]:

                        malicious = threat_intel["malicious"]
                        suspicious = threat_intel["suspicious"]

                        if malicious > 0:

                                score += 50

                                reasons.append(
                                        f"VirusTotal detected "
                                        f"{malicious} malicious result(s)"
                                )

                        if suspicious > 0:

                                score += 20

                                reasons.append(
                                        f"VirusTotal detected "
                                        f"{suspicious} suspicious result(s)"
                                )

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
                "score": score,
                "level": level,
                "reasons": reasons
        }
