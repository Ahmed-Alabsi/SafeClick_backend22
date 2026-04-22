"""
Dataset Loader (v4.1 - Streaming Optimized)
─────────────────────────────────────────────
Handles memory-efficient streaming of the 17M+ Master Whitelist.
Replaces "Load-and-Store" to prevent memory exhaustion and truncation.
"""

import csv
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "master_whitelist_clean.csv"

# Global cache for the prioritized list (Top 1M only to keep RAM low)
_RANKED_DOMAINS_CACHE = []

def stream_domains() -> Generator[str, None, None]:
    """
    Efficiently streams domains from the 307MB CSV file.
    Memory usage remains constant regardless of file size.
    """
    if not DATA_PATH.exists():
        logger.warning(f"Master whitelist not found at {DATA_PATH}")
        return

    try:
        with open(DATA_PATH, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            # Skip header
            header = next(reader, None)
            
            for row in reader:
                if not row: continue
                domain = row[0].strip().lower()
                if domain:
                    yield domain
    except Exception as e:
        logger.error(f"Error streaming domains: {e}")

def load_ranked_domains(limit: int = 1000000):
    """
    Loads a limited subset of top domains for memory-sensitive indexes (like Trie).
    Defaults to top 1M.
    """
    global _RANKED_DOMAINS_CACHE
    if _RANKED_DOMAINS_CACHE:
        return _RANKED_DOMAINS_CACHE

    logger.info(f"Loading top {limit} domains for search indexing...")
    count = 0
    for domain in stream_domains():
        _RANKED_DOMAINS_CACHE.append(domain)
        count += 1
        if count >= limit:
            break
            
    logger.info(f"Prioritized search index loaded: {len(_RANKED_DOMAINS_CACHE)} domains.")
    return _RANKED_DOMAINS_CACHE

# Safety Whitelist — guarantees critical brands are always indexed and fast-pathed.
# This list MUST remain comprehensive. Do NOT reduce it.
SAFETY_WHITELIST = frozenset([
    # Search & Tech Giants
    "google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
    "youtube.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    # Enterprise & IT
    "oracle.com", "ibm.com", "cisco.com", "intel.com", "nvidia.com", "tsmc.com",
    "hp.com", "dell.com", "lenovo.com", "vmware.com", "redhat.com", "splunk.com",
    "sap.com", "service-now.com", "workday.com", "salesforce.com", "atlassian.com",
    # Developer & Productivity
    "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
    "slack.com", "notion.so", "trello.com", "monday.com",
    "office.com", "zoom.us", "canva.com", "figma.com",
    # Entertainment & Social
    "netflix.com", "spotify.com", "tiktok.com", "reddit.com", "discord.com",
    "twitch.tv", "pinterest.com", "linkedin.com", "quora.com", "medium.com",
    # Finance & Commerce
    "paypal.com", "stripe.com", "shopify.com", "ebay.com", "etsy.com",
    "binance.com", "coinbase.com", "robinhood.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "hsbc.com", "visa.com", "mastercard.com",
    "goldmansachs.com", "jpmorgan.com", "citibank.com",
    # Cloud & Infrastructure
    "cloudflare.com", "digitalocean.com", "heroku.com", "akamai.com",
    "docker.com", "kubernetes.io", "terraform.io",
    # Google Platform & Infrastructure
    "appspot.com", "run.app", "web.app", "cloudfunctions.net",
    "firebaseapp.com", "googleapis.com", "googleusercontent.com",
    "googlesyndication.com", "gstatic.com", "withgoogle.com",
    # AI & Data
    "openai.com", "chatgpt.com", "anthropic.com", "huggingface.co", "midjourney.com",
    # News & Reference
    "wikipedia.org", "wikimedia.org", "bbc.com", "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com", "washingtonpost.com", "forbes.com",
    "bloomberg.com", "wsj.com", "aljazeera.com", "apnews.com",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "mit.edu", "stanford.edu", "harvard.edu", "oxford.ac.uk", "cam.ac.uk",
    # Science & Health
    "nature.com", "science.org", "nih.gov", "cdc.gov", "who.int",
    "mayoclinic.org", "webmd.com", "healthline.com",
    # Government
    "usa.gov", "gov.uk", "nasa.gov", "weather.gov", "un.org",
    "fbi.gov", "cia.gov", "irs.gov",
    # Utilities
    "adobe.com", "dropbox.com", "wordpress.com",
    "britannica.com", "espn.com", "weather.com", "accuweather.com",
    # Shopping
    "walmart.com", "target.com", "bestbuy.com", "costco.com", "ikea.com",
    "nike.com", "adidas.com", "homedepot.com", "lowes.com",
    # Gaming
    "steam.com", "steampowered.com", "epicgames.com", "roblox.com",
    "nintendo.com", "playstation.com",
    # Travel
    "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com",
    # Programming Languages
    "python.org", "rust-lang.org", "go.dev", "kotlinlang.org",
    "postgresql.org", "mysql.com", "redis.io", "mongodb.com",
    # Other important
    "kellybluebook.com", "ign.com", "gamespot.com", "techcrunch.com",
    "theverge.com", "wired.com", "arstechnica.com",
])