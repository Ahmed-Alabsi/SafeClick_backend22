# apps/domains/management/commands/seed_brand_catalog.py
"""
Brand Catalog Seeder (One-Time / Idempotent)
────────────────────────────────────────────
Populates the database Brand, BrandDomain, and BrandKeyword models from the
legacy constants and verified enterprise registries.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.domains.models import Brand, BrandDomain, BrandKeyword
from apps.domains.services.brand_service import BrandService

INITIAL_BRANDS = [
    # ── Saudi & MENA Banking & FinTech ────────────────────────────────────────
    {
        "name": "Al Rajhi Bank", "name_ar": "مصرف الراجحي", "slug": "alrajhibank",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["alrajhibank.com.sa", "alrajhi.bank"],
        "keywords": [
            ("alrajhibank", "TYPO_SIMILARITY", 1.0),
            ("alrajhi", "TYPO_SIMILARITY", 1.0),
            ("الراجحي", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Saudi National Bank (SNB)", "name_ar": "البنك الأهلي السعودي", "slug": "snb",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["alahli.com", "snb.com.sa", "alahlionline.com"],
        "keywords": [
            ("snb", "TOKEN_BOUNDARY", 1.0),
            ("alahli", "TYPO_SIMILARITY", 1.0),
            ("الأهلي", "CONTAINS", 0.9),
        ]
    },
    {
        "name": "Riyad Bank", "name_ar": "بنك الرياض", "slug": "riyadbank",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["riyadbank.com"],
        "keywords": [
            ("riyadbank", "TYPO_SIMILARITY", 1.0),
            ("بنك الرياض", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Alinma Bank", "name_ar": "مصرف الإنماء", "slug": "alinma",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["alinma.com"],
        "keywords": [
            ("alinma", "TYPO_SIMILARITY", 1.0),
            ("الإنماء", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Bank AlBilad", "name_ar": "بنك البلاد", "slug": "albilad",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["bankalbilad.com"],
        "keywords": [
            ("albilad", "TYPO_SIMILARITY", 1.0),
            ("bankalbilad", "TYPO_SIMILARITY", 1.0),
            ("البلاد", "CONTAINS", 0.9),
        ]
    },
    {
        "name": "Arab National Bank", "name_ar": "البنك العربي الوطني", "slug": "anb",
        "sector": "banking", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["anb.com.sa"],
        "keywords": [
            ("anb", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "stc pay", "name_ar": "إس تي سي باي", "slug": "stcpay",
        "sector": "fintech", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["stcpay.com.sa"],
        "keywords": [
            ("stcpay", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "urpay", "name_ar": "يورباي", "slug": "urpay",
        "sector": "fintech", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["urpay.com.sa"],
        "keywords": [
            ("urpay", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Commercial International Bank", "name_ar": "البنك التجاري الدولي", "slug": "cib",
        "sector": "banking", "country": "EG", "risk_weight": "CRITICAL",
        "domains": ["cibeg.com"],
        "keywords": [
            ("cib", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "Banque Misr", "name_ar": "بنك مصر", "slug": "banquemisr",
        "sector": "banking", "country": "EG", "risk_weight": "CRITICAL",
        "domains": ["banquemisr.com"],
        "keywords": [
            ("banquemisr", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "National Bank of Egypt", "name_ar": "البنك الأهلي المصري", "slug": "nbe",
        "sector": "banking", "country": "EG", "risk_weight": "CRITICAL",
        "domains": ["nbe.com.eg"],
        "keywords": [
            ("nbe", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "InstaPay Egypt", "name_ar": "إنستاباي", "slug": "instapay",
        "sector": "fintech", "country": "EG", "risk_weight": "CRITICAL",
        "domains": ["instapay.eg"],
        "keywords": [
            ("instapay", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Qatar National Bank", "name_ar": "بنك قطر الوطني", "slug": "qnb",
        "sector": "banking", "country": "QA", "risk_weight": "HIGH",
        "domains": ["qnb.com"],
        "keywords": [
            ("qnb", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "Abu Dhabi Commercial Bank", "name_ar": "بنك أبوظبي التجاري", "slug": "adcb",
        "sector": "banking", "country": "AE", "risk_weight": "HIGH",
        "domains": ["adcb.com"],
        "keywords": [
            ("adcb", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "First Abu Dhabi Bank", "name_ar": "بنك أبوظبي الأول", "slug": "bankfab",
        "sector": "banking", "country": "AE", "risk_weight": "HIGH",
        "domains": ["bankfab.com"],
        "keywords": [
            ("bankfab", "TYPO_SIMILARITY", 1.0),
            ("fab", "TOKEN_BOUNDARY", 0.9),
        ]
    },

    # ── Saudi Government & Critical Identity ──────────────────────────────────
    {
        "name": "Absher Platform", "name_ar": "منصة أبشر", "slug": "absher",
        "sector": "government", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["absher.sa"],
        "keywords": [
            ("absher", "TYPO_SIMILARITY", 1.0),
            ("أبشر", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Nafath National SSO", "name_ar": "نفاذ الوطني الموحد", "slug": "nafath",
        "sector": "government", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["nafath.sa", "iam.gov.sa"],
        "keywords": [
            ("nafath", "TYPO_SIMILARITY", 1.0),
            ("نفاذ", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Tawakkalna", "name_ar": "منظومة توكلنا", "slug": "tawakkalna",
        "sector": "government", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["tawakkalna.sa", "tawakkalna.sdaia.gov.sa"],
        "keywords": [
            ("tawakkalna", "TYPO_SIMILARITY", 1.0),
            ("توكلنا", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Qiwa Platform", "name_ar": "منصة قوى", "slug": "qiwa",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["qiwa.sa"],
        "keywords": [
            ("qiwa", "TOKEN_BOUNDARY", 1.0),
            ("قوى", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "Muqeem", "name_ar": "بوابة مقيم", "slug": "muqeem",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["muqeem.sa"],
        "keywords": [
            ("muqeem", "TYPO_SIMILARITY", 1.0),
            ("مقيم", "CONTAINS", 1.0),
        ]
    },
    {
        "name": "GOSI", "name_ar": "التأمينات الاجتماعية", "slug": "gosi",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["gosi.gov.sa"],
        "keywords": [
            ("gosi", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "ZATCA", "name_ar": "هيئة الزكاة والضريبة والجمارك", "slug": "zatca",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["zatca.gov.sa"],
        "keywords": [
            ("zatca", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "Balady Portal", "name_ar": "منصة بلدي", "slug": "balady",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["balady.gov.sa"],
        "keywords": [
            ("balady", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Etimad", "name_ar": "منصة اعتماد", "slug": "etimad",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["etimad.sa"],
        "keywords": [
            ("etimad", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Sehhaty", "name_ar": "صحتي", "slug": "sehhaty",
        "sector": "government", "country": "SA", "risk_weight": "HIGH",
        "domains": ["sehhaty.sa"],
        "keywords": [
            ("sehhaty", "TYPO_SIMILARITY", 1.0),
        ]
    },

    # ── Regional Telecom Providers ────────────────────────────────────────────
    {
        "name": "stc Group", "name_ar": "شركة الاتصالات السعودية", "slug": "stc",
        "sector": "telecom", "country": "SA", "risk_weight": "CRITICAL",
        "domains": ["stc.com.sa", "stc.com"],
        "keywords": [
            ("stc", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "Mobily", "name_ar": "موبايلي", "slug": "mobily",
        "sector": "telecom", "country": "SA", "risk_weight": "HIGH",
        "domains": ["mobily.com.sa"],
        "keywords": [
            ("mobily", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Zain", "name_ar": "زين", "slug": "zain",
        "sector": "telecom", "country": "SA", "risk_weight": "HIGH",
        "domains": ["sa.zain.com", "zain.com"],
        "keywords": [
            ("zain", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "e& / Etisalat", "name_ar": "اتصالات", "slug": "etisalat",
        "sector": "telecom", "country": "AE", "risk_weight": "HIGH",
        "domains": ["etisalat.ae", "eand.com", "etisalat.eg"],
        "keywords": [
            ("etisalat", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Orange", "name_ar": "أورنج", "slug": "orange",
        "sector": "telecom", "country": "EG", "risk_weight": "HIGH",
        "domains": ["orange.com", "orange.eg"],
        "keywords": [
            ("orange", "TOKEN_BOUNDARY", 0.8),
        ]
    },

    # ── E-Commerce & Delivery ─────────────────────────────────────────────────
    {
        "name": "Noon", "name_ar": "نون للتسوق", "slug": "noon",
        "sector": "ecommerce", "country": "SA", "risk_weight": "HIGH",
        "domains": ["noon.com"],
        "keywords": [
            ("noon", "TOKEN_BOUNDARY", 1.0),
        ]
    },
    {
        "name": "Jarir Bookstore", "name_ar": "مكتبة جرير", "slug": "jarir",
        "sector": "ecommerce", "country": "SA", "risk_weight": "HIGH",
        "domains": ["jarir.com"],
        "keywords": [
            ("jarir", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Hungerstation", "name_ar": "هنقرستيشن", "slug": "hungerstation",
        "sector": "delivery", "country": "SA", "risk_weight": "HIGH",
        "domains": ["hungerstation.com"],
        "keywords": [
            ("hungerstation", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Jahez", "name_ar": "جاهز", "slug": "jahez",
        "sector": "delivery", "country": "SA", "risk_weight": "HIGH",
        "domains": ["jahez.net"],
        "keywords": [
            ("jahez", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Talabat", "name_ar": "طلبات", "slug": "talabat",
        "sector": "delivery", "country": "AE", "risk_weight": "HIGH",
        "domains": ["talabat.com"],
        "keywords": [
            ("talabat", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Mrsool", "name_ar": "مرسول", "slug": "mrsool",
        "sector": "delivery", "country": "SA", "risk_weight": "HIGH",
        "domains": ["mrsool.co"],
        "keywords": [
            ("mrsool", "TYPO_SIMILARITY", 1.0),
        ]
    },

    # ── Global Tech & Finance ─────────────────────────────────────────────────
    {
        "name": "PayPal", "name_ar": "باي بال", "slug": "paypal",
        "sector": "fintech", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["paypal.com"],
        "keywords": [
            ("paypal", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Microsoft", "name_ar": "مايكروسوفت", "slug": "microsoft",
        "sector": "tech", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "onedrive.com"],
        "keywords": [
            ("microsoft", "TYPO_SIMILARITY", 1.0),
            ("office365", "TYPO_SIMILARITY", 1.0),
            ("onedrive", "TYPO_SIMILARITY", 1.0),
            ("outlook", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Apple", "name_ar": "آبل", "slug": "apple",
        "sector": "tech", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["apple.com", "icloud.com"],
        "keywords": [
            ("apple", "TOKEN_BOUNDARY", 0.9),
            ("icloud", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Google", "name_ar": "جوجل", "slug": "google",
        "sector": "tech", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["google.com", "youtube.com", "gmail.com"],
        "keywords": [
            ("google", "TYPO_SIMILARITY", 1.0),
            ("youtube", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Meta (Facebook / WhatsApp / Instagram)", "name_ar": "ميتا", "slug": "meta",
        "sector": "tech", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com"],
        "keywords": [
            ("facebook", "TYPO_SIMILARITY", 1.0),
            ("instagram", "TYPO_SIMILARITY", 1.0),
            ("whatsapp", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Amazon", "name_ar": "أمازون", "slug": "amazon",
        "sector": "ecommerce", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["amazon.com", "amazon.sa", "amazon.ae"],
        "keywords": [
            ("amazon", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "Binance", "name_ar": "بينانس", "slug": "binance",
        "sector": "crypto", "country": "GLOBAL", "risk_weight": "CRITICAL",
        "domains": ["binance.com"],
        "keywords": [
            ("binance", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "OpenAI / ChatGPT", "name_ar": "أوبن إيه آي", "slug": "openai",
        "sector": "tech", "country": "GLOBAL", "risk_weight": "HIGH",
        "domains": ["openai.com", "chatgpt.com"],
        "keywords": [
            ("openai", "TYPO_SIMILARITY", 1.0),
            ("chatgpt", "TYPO_SIMILARITY", 1.0),
        ]
    },
    {
        "name": "DHL Express", "name_ar": "دي إتش إل", "slug": "dhl",
        "sector": "delivery", "country": "GLOBAL", "risk_weight": "HIGH",
        "domains": ["dhl.com"],
        "keywords": [
            ("dhl", "TOKEN_BOUNDARY", 1.0),
        ]
    },
]


class Command(BaseCommand):
    help = "Seed initial verified brands, official domains, and detection keywords into the Brand Catalog."

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Seeding Brand Catalog..."))

        total_brands = 0
        total_domains = 0
        total_keywords = 0
        now = timezone.now()

        for data in INITIAL_BRANDS:
            brand, created = Brand.objects.update_or_create(
                slug=data["slug"],
                defaults={
                    "name": data["name"],
                    "name_ar": data.get("name_ar", ""),
                    "sector": data["sector"],
                    "country": data["country"],
                    "risk_weight": data["risk_weight"],
                    "is_active": True,
                }
            )
            total_brands += 1

            for domain_str in data["domains"]:
                b_domain, d_created = BrandDomain.objects.update_or_create(
                    domain=domain_str.strip().lower(),
                    defaults={
                        "brand": brand,
                        "status": "VERIFIED",
                        "verification_source": "LEGACY_SEED",
                        "verified_at": now,
                        "is_active": True,
                        "is_primary": (domain_str == data["domains"][0]),
                    }
                )
                total_domains += 1

            for kw_item in data["keywords"]:
                kw_str, strat, weight = kw_item
                b_kw, k_created = BrandKeyword.objects.update_or_create(
                    brand=brand,
                    keyword=kw_str.strip().lower(),
                    defaults={
                        "match_strategy": strat,
                        "weight": weight,
                        "is_active": True,
                    }
                )
                total_keywords += 1

        # Bump cache version
        BrandService.bump_version()

        self.stdout.write(self.style.SUCCESS(
            f"Successfully seeded Brand Catalog: {total_brands} brands, "
            f"{total_domains} official domains, {total_keywords} keywords."
        ))
