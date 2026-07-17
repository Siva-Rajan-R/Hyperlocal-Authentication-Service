import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PORT: int = 8010
    MONGO_URL: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "AuthenticationServiceDb"
    ENVIRONMENT: str = "development"
    DEB_APIKEY: str
    DEB_SECRETS: str
    FRONTEND_URL: str = "http://localhost:5173"

    class Config:
        env_file = ".env"
        extra = "ignore"

SETTINGS = Settings()
