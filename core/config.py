import logging
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class VanguardSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    # App Environment
    ENV: str = Field("production", pattern="^(development|production)$")
    DEBUG: bool = False
    
    # Security
    API_USER: str = "admin"
    API_PASSWORD_RAW: str = "vanguard123"
    JWT_SECRET_KEY: str = "super-secret-key-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12
    
    # Scanner Defaults
    DEFAULT_WORKERS: int = 500
    DEFAULT_TIMEOUT: float = 0.7
    BANNER_TIMEOUT: float = 0.8
    DEFAULT_DELAY: float = 0.0
    MAX_RETRIES: int = 2
    
    # Global Concurrency Limit
    GLOBAL_MAX_CONCURRENCY: int = 1000
    
    # Database
    DATABASE_PATH: str = "scans.db"
    DB_BATCH_SIZE: int = 50
    DB_QUEUE_MAX_SIZE: int = 5000
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "vanguard.log"

# Global Config Instance
Config = VanguardSettings()

def setup_logging():
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    
    # Custom format for professional look
    log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler()
        ]
    )
    
    # Suppress verbose 3rd party logs
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)
    logging.getLogger("passlib").setLevel(logging.ERROR)
    
    if Config.DEBUG:
        logging.getLogger("core.scanner").setLevel(logging.DEBUG)
