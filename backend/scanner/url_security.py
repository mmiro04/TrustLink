from urllib.parse import urlparse
import ipaddress
import socket


BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
}


def is_private_or_reserved_ip(ip):
    address = ipaddress.ip_address(ip)

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    )


def validate_url_for_request(url):
    parsed = urlparse(url)

    # Only allow HTTP and HTTPS
    if parsed.scheme not in {"http", "https"}:
        return False, "Only HTTP and HTTPS URLs are allowed"

    hostname = parsed.hostname

    if not hostname:
        return False, "URL does not contain a hostname"

    hostname = hostname.lower().rstrip(".")

    # Block known local hostnames
    if hostname in BLOCKED_HOSTS:
        return False, "Localhost access is blocked"

    # Direct IP address
    try:
        if is_private_or_reserved_ip(hostname):
            return False, "Private or reserved IP addresses are blocked"

        return True, None

    except ValueError:
        pass

    # Resolve hostname and check every returned address
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:
        return False, "Hostname could not be resolved"

    checked_addresses = set()

    for address in addresses:

        ip = address[4][0]

        if ip in checked_addresses:
            continue

        checked_addresses.add(ip)

        if is_private_or_reserved_ip(ip):
            return (
                False,
                "Hostname resolves to a private or reserved IP address"
            )

    return True, None
