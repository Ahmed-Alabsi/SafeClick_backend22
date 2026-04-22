"""
Shared Constants Module
───────────────────────
Single source of truth for constants shared across multiple engines.
Prevents duplication and ensures consistency.
"""

# Latin character pairs that visually mimic other characters
LATIN_TRICKS = {
    "rn": "m",   # rn looks like m
    "cl": "d",   # cl looks like d
    "vv": "w",   # vv looks like w
    "nn": "m",   # nn can look like m
    "1": "l",    # one looks like lowercase L
    "0": "o",    # zero looks like o
    "5": "s",    # 5 looks like S
    "!": "i",    # exclamation looks like i
}

# Brands that are frequent targets of impersonation attacks
SENSITIVE_BRANDS = frozenset([
    # Social Media
    "instagram", "facebook", "whatsapp", "twitter", "tiktok",
    "discord", "telegram", "snapchat", "linkedin", "pinterest",
    # Tech Giants
    "microsoft", "apple", "google", "amazon", "netflix",
    "outlook", "onedrive", "office365", "office",
    # Finance & Crypto
    "paypal", "stripe", "binance", "coinbase", "metamask",
    "blockchain", "trustwallet", "ledger", "trezor", "phantom",
    "chase", "wellsfargo", "bankofamerica",
    "capitalone", "hsbc", "citibank", "barclays",
    # Enterprise
    "oracle", "ibm", "cisco", "intel", "nvidia", "tsmc",
    # Cloud & Services
    "icloud", "dropbox", "salesforce", "adobe", "zoom",
    "slack", "shopify", "wordpress",
    # Gaming
    "steam", "steamcommunity", "roblox", "epicgames", "epic",
    # Delivery
    "fedex", "ups", "dhl", "usps",
    # AI
    "openai", "chatgpt",
])

# ──────────────────────────────────────────────────────────────────────────────
# Shared Hosting Providers (Multi-Tenant Platforms)
# ──────────────────────────────────────────────────────────────────────────────
# These are platforms where many independent users share ONE base domain.
# The subdomain IS the user identity, NOT the base domain.
#
# CRITICAL: Never block or match at the base-domain level for these.
#   - amazon-clone.vercel.app → malicious (specific subdomain)
#   - vercel.app              → NOT malicious (the entire platform)
#
# This list is defense-in-depth alongside tldextract/PSL.
# ──────────────────────────────────────────────────────────────────────────────
SHARED_HOSTING_PROVIDERS = frozenset([
    # ── Code Hosting & Static Deployment ──
    "github.io", "gitlab.io", "pages.dev", "codepen.io",
    "bitbucket.io",
    # ── Frontend Platforms ──
    "vercel.app", "netlify.app", "netlify.com", "surge.sh",
    # ── PaaS / Cloud Hosting ──
    "herokuapp.com", "fly.dev", "render.com", "railway.app",
    "onrender.com",
    # ── Google Cloud ──
    "firebaseapp.com", "web.app", "appspot.com",
    "run.app", "cloudfunctions.net",
    # ── Azure & AWS ──
    "azurewebsites.net", "blob.core.windows.net",
    "s3.amazonaws.com", "amplifyapp.com",
    "cloudfront.net",
    # ── Website Builders ──
    "webflow.io", "wixsite.com", "squarespace.com",
    "carrd.co", "strikingly.com", "weebly.com",
    "godaddysites.com", "myshopify.com",
    # ── Documentation & Knowledge ──
    "gitbook.io", "readthedocs.io", "notion.site",
    # ── IPFS & Decentralized ──
    "dweb.link", "ipfs.io", "fleek.co",
    # ── Tunneling & Dev ──
    "ngrok.io", "ngrok-free.app", "loca.lt",
    "duckdns.org", "trycloudflare.com",
    # ── URL Shorteners (never block the platform) ──
    "bit.ly", "tinyurl.com", "t.co", "rebrand.ly",
    "is.gd", "v.gd",
    # ── Misc ──
    "glitch.me", "replit.dev", "stackblitz.io",
    "blogspot.com", "wordpress.com",
])

# Country-code second-level domains (generic, not platform-specific)
COUNTRY_CODE_SLDS = frozenset([
    "us.com", "uk.com", "eu.com", "de.com", "jp.net", "ru.com",
    "ae.org", "hu.com", "kr.com", "qc.com", "uy.com", "za.com",
    "br.com", "cn.com", "sa.com", "se.com", "se.net", "uk.net",
    "gb.com", "gb.net", "no.com", "hu.net", "jpn.com", "gr.com",
    "co.com",
])
