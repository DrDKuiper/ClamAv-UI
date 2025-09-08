from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # Configurações de Aplicação
    APP_NAME: str = "ClamAV Web Panel"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Configurações de Segurança
    SECRET_KEY: str
    JWT_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    BCRYPT_ROUNDS: int = 12
    
    # Configurações de Banco de Dados
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379"
    
    # Configurações do ClamAV
    CLAMD_HOST: str = "localhost"
    CLAMD_PORT: int = 3310
    CLAMD_SOCKET: str = "/var/run/clamav/clamd.ctl"
    
    # Configurações de Email
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = True
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    # CVE API
    NVD_API_KEY: Optional[str] = None
    CVE_UPDATE_INTERVAL: int = 3600
    
    # Quarentena
    QUARANTINE_PATH: str = "/var/quarantine/clamav"
    MAX_QUARANTINE_SIZE_GB: int = 10
    
    # Monitoramento
    METRICS_RETENTION_DAYS: int = 30
    ALERT_EMAIL_RECIPIENTS: List[str] = []
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
