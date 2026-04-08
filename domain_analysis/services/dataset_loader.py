"""
Dataset Loader
──────────────
Loads the FULL Master Whitelist CSV into memory for Bloom Filter and Trie.

The master_whitelist.csv contains 17,438,941 domains. All are loaded to ensure
maximum whitelist coverage and minimize false positives.
"""

import csv
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "master_whitelist.csv"

TOP_DOMAINS = []


# Manual Safety Whitelist — guarantees critical brands are always indexed
SAFETY_WHITELIST = frozenset([
    # Search & Tech Giants
    "google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
    "youtube.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    # Developer & Productivity
    "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
    "slack.com", "notion.so", "trello.com", "atlassian.com", "monday.com",
    "office.com", "zoom.us", "canva.com", "figma.com",
    # Entertainment & Social
    "netflix.com", "spotify.com", "tiktok.com", "reddit.com", "discord.com",
    "twitch.tv", "pinterest.com", "linkedin.com", "quora.com", "medium.com",
    # Finance & Commerce
    "paypal.com", "stripe.com", "shopify.com", "ebay.com", "etsy.com",
    "binance.com", "coinbase.com", "robinhood.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com",
    # Cloud & Infrastructure
    "cloudflare.com", "digitalocean.com", "heroku.com",
    "docker.com", "kubernetes.io", "terraform.io",
    # AI & Data
    "openai.com", "chatgpt.com", "anthropic.com", "huggingface.co",
    # News & Reference
    "wikipedia.org", "wikimedia.org", "bbc.com", "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com", "washingtonpost.com", "forbes.com",
    "bloomberg.com", "wsj.com", "aljazeera.com", "apnews.com",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "mit.edu", "stanford.edu", "harvard.edu", "oxford.ac.uk",
    # Science & Health
    "nature.com", "science.org", "nih.gov", "cdc.gov", "who.int",
    "mayoclinic.org", "webmd.com", "healthline.com",
    # Government
    "usa.gov", "gov.uk", "nasa.gov", "weather.gov",
    # Utilities
    "adobe.com", "dropbox.com", "salesforce.com", "wordpress.com",
    "britannica.com", "espn.com", "weather.com", "accuweather.com",
    # Shopping
    "walmart.com", "target.com", "bestbuy.com", "costco.com", "ikea.com",
    "nike.com", "adidas.com", "homedepot.com", "lowes.com",
    # Gaming
    "steam.com", "steampowered.com", "epicgames.com", "roblox.com",
    # Travel
    "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com",
    # Programming Languages
    "python.org", "rust-lang.org", "go.dev", "kotlinlang.org",
    "postgresql.org", "mysql.com", "redis.io", "mongodb.com",
    # Other important
    "kellybluebook.com", "ign.com", "gamespot.com", "techcrunch.com",
    "theverge.com", "wired.com", "arstechnica.com",
])

def load_domains():
    global TOP_DOMAINS

    if TOP_DOMAINS:
        return TOP_DOMAINS

    try:
        with open(DATA_PATH, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)

            # Skip header if it exists
            first_row = next(reader, None)
            if first_row and first_row[0].lower() != "domain":
                TOP_DOMAINS.append(first_row[0].strip().lower())

            for row in reader:
                if not row:
                    continue

                domain = row[0].strip().lower()
                if domain:
                    TOP_DOMAINS.append(domain)

        logger.info(f"Dataset loaded: {len(TOP_DOMAINS)} domains from {DATA_PATH.name}")

    except FileNotFoundError:
        logger.warning(f"Dataset not found: {DATA_PATH}. Starting with safety whitelist only.")

    top_domains_set = set(TOP_DOMAINS)
    added = 0
    for d in SAFETY_WHITELIST:
        if d not in top_domains_set:
            TOP_DOMAINS.append(d)
            top_domains_set.add(d)
            added += 1

    if added:
        logger.info(f"Safety whitelist: added {added} critical domains")

    return TOP_DOMAINS