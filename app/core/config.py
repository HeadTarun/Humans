import logging
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db"
    SECRET_KEY: str = ""
    GROQ_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    IPINFO_TOKEN: str = ""
    MAX_LLM_TOKENS: int = 4000  # Default budget for Groq in Stage 8
    INVESTIGATION_MAX_LATENCY_MS: int = 4000
    INVESTIGATION_MAX_TOOL_CALLS: int = 8
    INVESTIGATION_MAX_EXTERNAL_CALLS: int = 4
    GEOLOCATION_EXTERNAL_ENABLED: bool = True
    GEOLOCATION_TIMEOUT_SECONDS: float = 1.5
    GEOLOCATION_CACHE_TTL_SECONDS: int = 3600
    GEOIP_CITY_DB_PATH: str = "GeoLite2-City.mmdb"
    GEOIP_ASN_DB_PATH: str = "GeoLite2-ASN.mmdb"
    GOOGLE_CLOUD_PROJECT: str | None = None

    # CORS — comma-separated list of allowed origins.
    # Example: "http://localhost:3000,http://localhost:8501"
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:8501,http://localhost:5173"

    # Supabase Storage bucket for raw .eml preservation (optional).
    SUPABASE_BUCKET_NAME: str = "email-artifacts"
    # Supabase project URL, e.g. https://<project>.supabase.co
    SUPABASE_URL: str = ""
    # Service-role key (NOT anon key) — required for private bucket access.
    SUPABASE_SERVICE_KEY: str = ""

    # JWT settings for user authentication
    JWT_SECRET_KEY: str = ""          # Falls back to SECRET_KEY when empty
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24 hours default

    # Logging level for the application.
    LOG_LEVEL: str = "INFO"

    # Demo mode — bypasses authentication for SIH demonstration.
    # MUST be false in production.
    DEMO_MODE: bool = False

    # ----- Reasoning Layer (LangChain + Groq) -----
    GROQ_REASONING_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_REASONING_TIMEOUT_SECONDS: int = 30
    GROQ_REASONING_MAX_TOKENS: int = 2048
    REASONING_ENABLED: bool = True
    REASONING_AUTO_TRIGGER_ENABLED: bool = True
    REASONING_CONFIDENCE_THRESHOLD: float = 0.6
    REASONING_PROMPT_VERSION: str = "1.0"

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }

    @property
    def cors_origins_list(self) -> List[str]:
        """Return CORS_ALLOWED_ORIGINS as a parsed list."""
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]


settings = Settings()


def log_optional_provider_diagnostics() -> None:
    """Report configuration gaps without ever logging credential values."""
    logger = logging.getLogger(__name__)
    for name, configured in {
        "GROQ_API_KEY": bool(settings.GROQ_API_KEY),
        "VIRUSTOTAL_API_KEY": bool(settings.VIRUSTOTAL_API_KEY),
        "ABUSEIPDB_API_KEY": bool(settings.ABUSEIPDB_API_KEY),
        "IPINFO_TOKEN": bool(settings.IPINFO_TOKEN),
    }.items():
        if not configured:
            logger.warning("Optional provider disabled: %s is not configured", name)
    if not settings.SECRET_KEY or settings.SECRET_KEY.startswith("replace-with-"):
        logger.warning(
            "SECRET_KEY is not configured; authenticated API routes will reject all requests"
        )

