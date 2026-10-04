import ipaddress
from urllib.parse import urlparse
from rest_framework import serializers

FORBIDDEN_HOSTNAMES = frozenset([
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"
])

def is_private_or_internal_ip(ip_str: str) -> bool:
    """Checks if an IP string is private, loopback, link-local (cloud metadata), or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified or
            str(ip) == "169.254.169.254"
        )
    except ValueError:
        return False

def resolve_and_check_ip_safety(hostname: str) -> tuple[bool, str]:
    """Resolves hostname via DNS and verifies none of the resolved IPs are internal/private (DNS Rebinding SSRF Protection)."""
    import socket
    if not hostname:
        return False, "اسم النطاق فارغ"
    
    hostname_clean = hostname.strip().lower().strip(".")
    if hostname_clean in FORBIDDEN_HOSTNAMES or hostname_clean.endswith((".local", ".internal", ".localhost")):
        return False, "الوصول إلى عناوين محلية أو داخلية محظور"

    if is_private_or_internal_ip(hostname_clean):
        return False, "عنوان IP خاص أو محلي محظور"

    try:
        addr_info = socket.getaddrinfo(hostname_clean, None, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            ip = item[4][0]
            if is_private_or_internal_ip(ip):
                return False, f"النطاق يشير إلى عنوان IP داخلي محظور ({ip})"
    except socket.gaierror:
        # Cannot resolve hostname: not an internal private IP violation
        pass
    except Exception as e:
        return False, f"فشل التحقق من أمان النطاق: {e}"

    return True, ""

def is_safe_redirect_url(url: str) -> tuple[bool, str]:
    """Validates URL structure, credentials, and DNS resolution against SSRF attacks."""
    if not url or not isinstance(url, str):
        return False, "رابط غير صالح"

    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ["http", "https"]:
            return False, "يجب أن يبدأ الرابط بـ http:// أو https://"

        hostname = parsed.hostname
        if not hostname:
            return False, "الرابط لا يحتوي على اسم نطاق صالح"

        if parsed.username or parsed.password:
            return False, "الروابط التي تحتوي على بيانات مصادقة مدمجة غير مسموح بها"

        safe, reason = resolve_and_check_ip_safety(hostname)
        if not safe:
            return False, reason

        return True, ""
    except Exception as e:
        return False, f"خطأ في التحقق من أمان الرابط: {e}"

def validate_safe_url(value: str) -> str:
    """
    Validates that a URL is well-formed and does not target internal network,
    loopback, or cloud metadata endpoints (SSRF Defense).
    """
    safe, reason = is_safe_redirect_url(value)
    if not safe:
        raise serializers.ValidationError(reason)
    return value

