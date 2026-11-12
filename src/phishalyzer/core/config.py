
"""Application configuration and environment validation."""

from functools import lru_cache
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class Settings(BaseSettings):
    """Validated application settings."""

    app_name: str = "Phishalyzer"
    app_env: Literal["development", "testing", "production"] = "development"
    log_level: Literal[
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
    ] = "INFO"

    virustotal_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None

    request_timeout: int = Field(default=10, ge=1, le=60)
    max_redirects: int = Field(default=5, ge=0, le=10)

    risk_low_max: int = Field(default=24, ge=0, le=100)
    risk_moderate_max: int = Field(default=49, ge=1, le=100)
    risk_high_max: int = Field(default=74, ge=1, le=100)
    risk_critical_max: int = Field(default=100, ge=1, le=100)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    def validate_risk_thresholds(self) -> None:
        """Ensure risk thresholds are strictly increasing and end at 100."""

        thresholds = [
            self.risk_low_max,
            self.risk_moderate_max,
            self.risk_high_max,
            self.risk_critical_max,
        ]

        if thresholds != sorted(set(thresholds)):
            raise ValueError(
                "Risk thresholds must be strictly increasing."
            )

        if self.risk_critical_max != 100:
            raise ValueError(
                "The critical risk threshold must be 100."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached, validated application settings."""

    settings = Settings()
    settings.validate_risk_thresholds()
    return settings
