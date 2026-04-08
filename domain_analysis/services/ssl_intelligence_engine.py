"""
SSL/TLS Intelligence Engine
────────────────────────────
Analyzes SSL/TLS certificates for security indicators.

Design Decision:
    Single-connection approach using the `cryptography` library to parse
    the DER-encoded certificate from an unverified connection. This eliminates
    the previous double-handshake (first CERT_NONE, then verified) which
    doubled latency.

    Alternatives considered:
    1. Double-connect (old approach) — 2x latency, wastes resources
    2. pyOpenSSL — powerful but heavy dependency, being deprecated
    3. ssl + cryptography (chosen) — single connect, parse DER cert in-memory
    4. sslyze — full audit tool, overkill for our use case

    → Chosen: ssl module for connection + cryptography for DER parsing.
      Best performance with accurate cert analysis.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Lazy import to avoid startup cost if engine is not used
_crypto_available = None
_x509 = None


def _ensure_crypto():
    """Lazy-load the cryptography library."""
    global _crypto_available, _x509
    if _crypto_available is None:
        try:
            from cryptography import x509 as _x509_mod
            _x509 = _x509_mod
            _crypto_available = True
        except ImportError:
            _crypto_available = False
            logger.warning("cryptography library not available; SSL cert details will be limited")


def analyze_ssl(domain: str) -> Dict[str, Any]:
    """
    Analyzes the SSL/TLS certificate of the given domain using a single connection.
    Checks for: certificate presence, expiration, self-signed status, issuer, and TLS version.
    """
    if not domain:
        return {
            "status": "error",
            "error": "No domain provided",
            "details": {"has_ssl": False}
        }

    details = {
        "has_ssl": False,
        "is_self_signed": False,
        "is_expired": False,
        "expiration_days": None,
        "issuer": None,
        "subject": None,
        "protocol": None,
        "errors": []
    }

    _ensure_crypto()

    try:
        # Single connection with CERT_NONE to get the cert even if invalid
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=2.5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                details["has_ssl"] = True
                details["protocol"] = ssock.version()

                # Get the DER-encoded certificate
                der_cert = ssock.getpeercert(binary_form=True)

                if der_cert and _crypto_available and _x509:
                    try:
                        cert = _x509.load_der_x509_certificate(der_cert)

                        # Extract issuer common name
                        try:
                            issuer_cn = cert.issuer.get_attributes_for_oid(
                                _x509.oid.NameOID.COMMON_NAME
                            )
                            details["issuer"] = issuer_cn[0].value if issuer_cn else str(cert.issuer)
                        except Exception:
                            details["issuer"] = str(cert.issuer)

                        # Extract subject common name
                        try:
                            subject_cn = cert.subject.get_attributes_for_oid(
                                _x509.oid.NameOID.COMMON_NAME
                            )
                            details["subject"] = subject_cn[0].value if subject_cn else str(cert.subject)
                        except Exception:
                            details["subject"] = str(cert.subject)

                        # Self-signed detection: issuer == subject
                        details["is_self_signed"] = (cert.issuer == cert.subject)

                        # Expiration check
                        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        details["expiration_days"] = (not_after - now).days
                        details["is_expired"] = details["expiration_days"] < 0

                    except Exception as e:
                        details["errors"].append(f"Certificate parsing: {type(e).__name__}")
                        logger.debug(f"Cert parsing error for {domain}: {e}")

                elif der_cert:
                    # Fallback: try verified connection for getpeercert() dict
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((domain, 443), timeout=2.0) as sock2:
                            with ctx2.wrap_socket(sock2, server_hostname=domain) as ssock2:
                                cert_data = ssock2.getpeercert()
                                if cert_data:
                                    # Issuer
                                    issuer = cert_data.get("issuer")
                                    if issuer:
                                        try:
                                            details["issuer"] = issuer[0][0][1]
                                        except (IndexError, TypeError):
                                            details["issuer"] = str(issuer)

                                    # Expiration
                                    not_after_str = cert_data.get("notAfter")
                                    if not_after_str:
                                        not_after = datetime.strptime(
                                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                                        ).replace(tzinfo=timezone.utc)
                                        now = datetime.now(timezone.utc)
                                        details["expiration_days"] = (not_after - now).days
                                        details["is_expired"] = details["expiration_days"] < 0
                    except ssl.SSLCertVerificationError as e:
                        if "self signed" in str(e).lower() or "self-signed" in str(e).lower():
                            details["is_self_signed"] = True
                        details["errors"].append(f"Verification: {type(e).__name__}")
                    except Exception as e:
                        details["errors"].append(f"Fallback detail extraction: {type(e).__name__}")

    except socket.timeout:
        details["errors"].append("Connection timed out")
    except ConnectionRefusedError:
        details["errors"].append("Connection refused (port 443)")
    except OSError as e:
        details["errors"].append(f"Network error: {type(e).__name__}")
    except Exception as e:
        details["errors"].append(f"Connection failed: {type(e).__name__}")

    return {
        "status": "ok",
        "details": details
    }