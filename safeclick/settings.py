"""
Django settings for safeclick project - النسخة النهائية المتكاملة
"""

from pathlib import Path
import os
import sys
from dotenv import load_dotenv
from datetime import timedelta
from django.urls import reverse_lazy
from django.templatetags.static import static

# Load environment variables
load_dotenv()

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# ========== الأمان ==========
DEBUG = os.getenv('DJANGO_DEBUG', 'True') == 'True'
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-dev-key-change-in-production')
IS_TESTING = 'test' in sys.argv or 'pytest' in sys.argv[0]

# Production security assertion: Never run in production with default insecure key
if not DEBUG and SECRET_KEY == 'django-insecure-dev-key-change-in-production':
    raise ValueError("CRITICAL SECURITY ERROR: SECRET_KEY must be set to a strong unpredictable key in production!")

# Production Safety Net: Crash immediately if critical secrets are missing
if not DEBUG and not IS_TESTING:
    _REQUIRED_SECRETS = ['SECRET_KEY', 'DB_PASSWORD', 'DB_HOST']
    _missing = [s for s in _REQUIRED_SECRETS if not os.getenv(s)]
    if _missing:
        raise ValueError(
            f"CRITICAL: Missing required environment variables for production: "
            f"{', '.join(_missing)}. Refusing to start."
        )

# DEVELOPMENT: Allow all hosts so physical devices on the LAN can connect.
# PRODUCTION: Set ALLOWED_HOSTS env var to your exact domain, e.g. 'safeclick.app'
if DEBUG or IS_TESTING:
    ALLOWED_HOSTS = ['*']
else:
    allowed = [h.strip() for h in os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',') if h.strip()]
    # Automatically trust Render domains
    if '.onrender.com' not in allowed:
        allowed.append('.onrender.com')
    ALLOWED_HOSTS = allowed

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
APP_ID = os.getenv('APP_ID', 'safeclick-flutter-client')
APP_SECRET = os.getenv('APP_SECRET', '')

# Guest JWT uses a SEPARATE signing key (defense in depth)
GUEST_JWT_SECRET = os.getenv('GUEST_JWT_SECRET', SECRET_KEY + '-guest-ns')
GUEST_JWT_TTL_HOURS = int(os.getenv('GUEST_JWT_TTL_HOURS', '48'))


# ========== التطبيقات ==========
INSTALLED_APPS = [
    'unfold',
    'unfold.contrib.filters',
    'unfold.contrib.forms',
    'unfold.contrib.inlines',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third party
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_spectacular',

    # Local apps
    'apps.accounts',
    'apps.scans.apps.ScansConfig',
    'apps.reports',
    'apps.core',
    'apps.feedback',
    'apps.domains',        # Domain intelligence
    'apps.ai',             # AI model management
    'apps.monitoring',     # Engine health monitoring
    'domain_analysis',     # Heuristic analysis engines
    'apps.admin_api',      # Headless Admin Dashboard APIs
]

# ========== Middleware ==========
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # High performance static file serving
    'corsheaders.middleware.CorsMiddleware',
    'safeclick.middleware.AppAccessMiddleware',  # Phase 6: App-ID validation
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'safeclick.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'safeclick.wsgi.application'

# ========== قاعدة البيانات ==========
if 'test' in sys.argv or 'pytest' in sys.argv[0]:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }
elif os.getenv('DATABASE_URL'):
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.config(
            default=os.getenv('DATABASE_URL'),
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
elif os.getenv('USE_SQLITE', 'False').lower() in ('true', '1'):
    # Fast testing fallback without external database
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    # الاعتماد حصراً على PostgreSQL للبيئات الحية والتطويرية
    DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ========== التخزين المؤقت (Redis) ==========
REDIS_URL = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1')

try:
    import django_redis
    import redis

    # Ping Redis to see if it's alive
    redis_test_client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2.0)
    redis_test_client.ping()

    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "IGNORE_EXCEPTIONS": True,
                "SOCKET_CONNECT_TIMEOUT": 2,
                "SOCKET_TIMEOUT": 2,
            },
            "KEY_PREFIX": "safeclick",
        }
    }
except Exception as e:
    # Redis not available — fallback to in-memory cache
    import logging
    logging.getLogger(__name__).warning(
        f"Redis unavailable ({type(e).__name__}). Falling back to LocMemCache."
    )
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# ========== التحقق من كلمة المرور ==========
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,  # NIST SP 800-63B standard minimum
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ========== اللغة والوقت ==========
LANGUAGE_CODE = 'ar'
TIME_ZONE = 'Asia/Riyadh'
USE_I18N = True
USE_TZ = True

# ========== الملفات الثابتة ==========
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# ========== ملفات الوسائط ==========
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# ========== المفتاح الأساسي ==========
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ========== نموذج المستخدم ==========
AUTH_USER_MODEL = 'accounts.User'

# ========== REST Framework ==========
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.core.pagination.StandardPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        # SECURITY: BrowsableAPIRenderer disabled — can expose tokens in HTML.
        # Re-enable ONLY during local development.
        # 'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.FormParser',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',  # Phase 7: per-endpoint limits
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '50/hour',
        'user': '100/hour',
        'scan': '10/minute',  # Phase 7: 10 scans/min per authenticated user
        'guest_scan': '3/day',  # Allow 3 scans per day for guests based on IP
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DATETIME_FORMAT': '%Y-%m-%d %H:%M:%S',
}

# ========== OpenAPI / Swagger Settings ==========
SPECTACULAR_SETTINGS = {
    'TITLE': 'SafeClick Threat Intelligence API',
    'DESCRIPTION': 'Multi-Layer Phishing, Threat Detection & URL Security Intelligence API',
    'VERSION': '2.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_PATH_PREFIX': r'/api/',
}

# ========== حدود الاستخدام ==========
FREE_GUEST_SCANS_LIMIT = 3

DEFAULT_CHARSET = 'utf-8'

# ========== JWT Settings ==========
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=int(os.getenv('JWT_ACCESS_TOKEN_MINUTES', '60'))),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=int(os.getenv('JWT_REFRESH_TOKEN_DAYS', '14'))),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    
    # إضافات مهمة لتجربة المستخدم
    'UPDATE_LAST_LOGIN': True,           # تحديث آخر دخول مع كل طلب
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# ========== CORS Settings ==========
# Default to permissive ONLY when DEBUG is explicitly True
default_cors_allow_all = 'True' if DEBUG else 'False'
CORS_ALLOW_ALL_ORIGINS = os.getenv('CORS_ALLOW_ALL_ORIGINS', default_cors_allow_all) == 'True'
CORS_ALLOW_CREDENTIALS = True

default_allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://192.168.1.102:3000",
    "http://192.168.1.102:8000",
]
env_cors_origins = [o.strip() for o in os.getenv('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
CORS_ALLOWED_ORIGINS = env_cors_origins if env_cors_origins else default_allowed_origins

# ========== CSRF Settings ==========
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.1.102:3000",
    "http://192.168.1.102:8000",
    "https://*.onrender.com",
]
env_csrf = [o.strip() for o in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if o.strip()]
if env_csrf:
    CSRF_TRUSTED_ORIGINS.extend(env_csrf)

# ========== API Keys ==========
# Note: VIRUSTOTAL_API_KEY and GOOGLE_SAFE_BROWSING_API_KEY already defined above (line 27-28)
GOOGLE_WEB_CLIENT_ID = os.getenv('GOOGLE_WEB_CLIENT_ID', '')

# ========== Email Settings (Gmail SMTP) ==========
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'SafeClick <safeclick17@gmail.com>')

# ========== Logging ==========
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'django.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'scans': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# ========== Django Unfold Cybersecurity Console Settings ==========
UNFOLD = {
    "SITE_TITLE": "SafeClick Cyber Intelligence",
    "SITE_HEADER": "SafeClick Security Console",
    "SITE_SUBHEADER": "منظومة كشف التصيد واستخبارات العلامات التجارية والنطاقات",
    "SITE_SYMBOL": "shield",
    "SITE_URL": "/",
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": True,
    "THEME": "light",
    "ENVIRONMENT": "safeclick.admin_dashboard.environment_callback",
    "DASHBOARD_CALLBACK": "safeclick.admin_dashboard.dashboard_callback",
    "COLORS": {
        "primary": {
            "50": "#eff6ff",
            "100": "#dbeafe",
            "200": "#bfdbfe",
            "300": "#93c5fd",
            "400": "#60a5fa",
            "500": "#3b82f6",
            "600": "#2563eb",
            "700": "#1d4ed8",
            "800": "#1e40af",
            "900": "#1e3a8a",
            "950": "#172554",
        },
        "base": {
            "50": "#f8fafc",
            "100": "#f1f5f9",
            "200": "#e2e8f0",
            "300": "#cbd5e1",
            "400": "#94a3b8",
            "500": "#64748b",
            "600": "#475569",
            "700": "#334155",
            "800": "#1e293b",
            "900": "#0f172a",
            "950": "#020617",
        },
    },
    "STYLES": [
        lambda request: static("admin/css/safeclick_theme.css") + "?v=2.2",
    ],
    "SIDEBAR": {
        "show_search": False,
        "show_all_applications": False,
        "navigation": [
            {
                "title": "استخبارات العلامات والنطاقات",
                "separator": True,
                "collapsible": True,
                "items": [
                    {
                        "title": "العلامات التجارية المحمية",
                        "icon": "verified_user",
                        "link": reverse_lazy("admin:domains_brand_changelist"),
                    },
                    {
                        "title": "نطاقات العلامات الرسمية",
                        "icon": "domain",
                        "link": reverse_lazy("admin:domains_branddomain_changelist"),
                    },
                    {
                        "title": "الكلمات المفتاحية الحساسة",
                        "icon": "key",
                        "link": reverse_lazy("admin:domains_brandkeyword_changelist"),
                    },
                    {
                        "title": "سجل النطاقات المفحوصة",
                        "icon": "language",
                        "link": reverse_lazy("admin:domains_domain_changelist"),
                    },
                    {
                        "title": "البيانات التقنية والاستخباراتية",
                        "icon": "dns",
                        "link": reverse_lazy("admin:domains_domainintel_changelist"),
                    },
                ],
            },
            {
                "title": "محرك الفحص ومكافحة التهديدات",
                "separator": True,
                "collapsible": True,
                "items": [
                    {
                        "title": "سجل الفحوصات الأمنية",
                        "icon": "travel_explore",
                        "link": reverse_lazy("admin:scans_scan_changelist"),
                    },
                    {
                        "title": "نتائج محركات الفحص الخارجية",
                        "icon": "analytics",
                        "link": reverse_lazy("admin:scans_scansourceresult_changelist"),
                    },
                    {
                        "title": "القائمة السوداء النشطة",
                        "icon": "block",
                        "link": reverse_lazy("admin:scans_blacklist_changelist"),
                    },
                    {
                        "title": "القائمة البيضاء المعتمدة",
                        "icon": "check_circle",
                        "link": reverse_lazy("admin:scans_whitelistentry_changelist"),
                    },
                    {
                        "title": "كاش الفحوصات السريعة",
                        "icon": "cached",
                        "link": reverse_lazy("admin:scans_scancache_changelist"),
                    },
                ],
            },
            {
                "title": "مركز البلاغات وملاحظات المجتمع",
                "separator": True,
                "collapsible": True,
                "items": [
                    {
                        "title": "بلاغات الروابط المشبوهة",
                        "icon": "flag",
                        "link": reverse_lazy("admin:reports_report_changelist"),
                    },
                    {
                        "title": "تعليقات ومتابعة البلاغات",
                        "icon": "forum",
                        "link": reverse_lazy("admin:reports_reportcomment_changelist"),
                    },
                    {
                        "title": "تقييمات وملاحظات التطبيق",
                        "icon": "star",
                        "link": reverse_lazy("admin:feedback_apprating_changelist"),
                    },
                ],
            },
            {
                "title": "الذكاء الاصطناعي ومراقبة المحركات",
                "separator": True,
                "collapsible": True,
                "items": [
                    {
                        "title": "نماذج الذكاء الاصطناعي",
                        "icon": "psychology",
                        "link": reverse_lazy("admin:ai_aimodelversion_changelist"),
                    },
                    {
                        "title": "بيانات التدريب والتحقق",
                        "icon": "database",
                        "link": reverse_lazy("admin:ai_aitrainingdataset_changelist"),
                    },
                    {
                        "title": "سجل تنبؤات النماذج",
                        "icon": "batch_prediction",
                        "link": reverse_lazy("admin:ai_aiprediction_changelist"),
                    },
                    {
                        "title": "سجل صحة المحركات",
                        "icon": "monitor_heart",
                        "link": reverse_lazy("admin:monitoring_enginehealthlog_changelist"),
                    },
                ],
            },
            {
                "title": "المستخدمون والأمان وجلسات الزوار",
                "separator": True,
                "collapsible": True,
                "items": [
                    {
                        "title": "مستخدمو المنصة",
                        "icon": "person",
                        "link": reverse_lazy("admin:accounts_user_changelist"),
                    },
                    {
                        "title": "جلسات الزوار وحصص الفحص",
                        "icon": "badge",
                        "link": reverse_lazy("admin:accounts_guestsession_changelist"),
                    },
                    {
                        "title": "رموز التحقق وسجلات الأمان",
                        "icon": "mark_email_read",
                        "link": reverse_lazy("admin:accounts_emailverification_changelist"),
                    },
                    {
                        "title": "سجلات عناوين IP المقيدة",
                        "icon": "policy",
                        "link": reverse_lazy("admin:accounts_ipattempt_changelist"),
                    },
                ],
            },
        ],
    },
}

# ========== Security Configuration ==========
# Safe threshold to prevent memory exhaustion DoS attacks
DATA_UPLOAD_MAX_NUMBER_FIELDS = int(os.getenv('DATA_UPLOAD_MAX_NUMBER_FIELDS', '2000'))

# ========== Production Security Headers & SSL Hardening ==========
if not DEBUG and not IS_TESTING:
    SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', 'True') == 'True'
    SECURE_HSTS_SECONDS = int(os.getenv('SECURE_HSTS_SECONDS', '31536000'))  # 1 year HSTS
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
else:
    SECURE_SSL_REDIRECT = False

# ========== Email Verification Policy ==========
# Mandate email OTP verification before issuing active JWT tokens
REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'True') == 'True'
