import socket
import ssl
from datetime import datetime, timezone

def analyze_ssl(domain: str, port: int = 443):

	result = {
		"domain": domain,
		"port": port,
		"valid": False,
		"issuer": None,
		"subject": None,
		"expires": None,
		"days_until_expiry": None,
		"tls_version": None,
		"error": None
	}

	try:
		context = ssl.create_default_context()
		
		with socket.create_connection(
			(domain,port),
			timeout = 5
		) as sock:
			
			with context.wrap_socket(
				sock,
				server_hostname=domain
			) as secure_sock:

				certificate = secure_sock.getpeercert()

				result["valid"] = True
				result["tls_version"] = secure_sock.version()

				result["issuer"] = certificate.get("issuer")
				result["subject"] = certificate.get("subject")

				expires = certificate.get("notAfter")

				result["expires"] = expires

				if expires:
					expiry_date = datetime.strptime(
						expires,
						"%b %d %H:%M:%S %Y %Z"
					).replace(tzinfo=timezone.utc)


					result["days_until_expiry"] = (
						expiry_date - datetime.now(timezone.utc)
					).days

	except Exception as e:
		result["error"] = str(e)
	
	return result
