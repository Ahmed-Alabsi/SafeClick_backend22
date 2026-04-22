"""
SSL/TLS Intelligence Engine
────────────────────────────
Analyzes SSL/TLS certificates for security indicators.

Design Decision:
    Single-connection approach using `asyncio.open_connection` and `cryptography`
    to parse the DER-encoded certificate from an unverified ssl context.
    Best performance with accurate cert analysis and completely asynchronous.
"""

import ssl
import asyncio
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


async def analyze_ssl(domain: str) -> Dict[str, Any]:
    """
    Analyzes the SSL/TLS certificate of the given domain asynchronously.
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
        "cert_age_days": None,
        "issuer": None,
        "subject": None,
        "protocol": None,
        "errors": []
    }

    _ensure_crypto()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    reader, writer = None, None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=context, server_hostname=domain),
            timeout=2.5
        )
        
        ssl_obj = writer.get_extra_info('ssl_object')
        details["has_ssl"] = True
        details["protocol"] = ssl_obj.version()

        der_cert = ssl_obj.getpeercert(binary_form=True)

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

                # Self-signed detection
                details["is_self_signed"] = (cert.issuer == cert.subject)

                # Expiration and Age check
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                
                details["expiration_days"] = (not_after - now).days
                details["is_expired"] = details["expiration_days"] < 0
                details["cert_age_days"] = (now - not_before).days

            except Exception as e:
                details["errors"].append(f"Certificate parsing: {type(e).__name__}")
                logger.debug(f"Cert parsing error for {domain}: {e}")

        elif der_cert:
            # Fallback for getting dict fields requires a verified connection
            # We will close this connection and open a verified one
            writer.close()
            await writer.wait_closed()
            
            try:
                ctx2 = ssl.create_default_context()
                reader2, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(domain, 443, ssl=ctx2, server_hostname=domain),
                    timeout=2.0
                )
                ssl_obj2 = writer2.get_extra_info('ssl_object')
                cert_data = ssl_obj2.getpeercert()
                if cert_data:
                    issuer = cert_data.get("issuer")
                    if issuer:
                        try:
                            details["issuer"] = issuer[0][0][1]
                        except (IndexError, TypeError):
                            details["issuer"] = str(issuer)

                    not_after_str = cert_data.get("notAfter")
                    not_before_str = cert_data.get("notBefore")
                    now = datetime.now(timezone.utc)
                    
                    if not_after_str:
                        not_after = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        details["expiration_days"] = (not_after - now).days
                        details["is_expired"] = details["expiration_days"] < 0
                        
                    if not_before_str:
                        not_before = datetime.strptime(
                            not_before_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        details["cert_age_days"] = (now - not_before).days
                
                writer2.close()
                await writer2.wait_closed()

            except ssl.SSLCertVerificationError as e:
                if "self signed" in str(e).lower() or "self-signed" in str(e).lower():
                    details["is_self_signed"] = True
                details["errors"].append(f"Verification: {type(e).__name__}")
            except Exception as e:
                details["errors"].append(f"Fallback detail extraction: {type(e).__name__}")

    except asyncio.TimeoutError:
        details["errors"].append("Connection timed out")
    except ConnectionRefusedError:
        details["errors"].append("Connection refused (port 443)")
    except OSError as e:
        details["errors"].append(f"Network error: {type(e).__name__}")
    except Exception as e:
        details["errors"].append(f"Connection failed: {type(e).__name__}")
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return {
        "status": "ok",
        "details": details
    }