from pydantic import BaseSettings
from typing import List


class Settings(BaseSettings):
    ad_servers: List[str] = []
    ad_certs: List[str] = []  # Paths to cert files
    ad_username: str = ""
    ad_password: str = ""
    ad_ou: str = ""
    db_url: str = "postgresql+psycopg2://user:password@postgres-service:5432/userdb"
    secret_key: str = "change_me"

    admin_username: str = "admin"
    admin_password: str = "adminpass"

    class Config:
        env_file = ".env"

settings = Settings()
