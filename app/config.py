from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    ad_servers: List[str] = []
    ad_certs: List[str] = []  # Paths to cert files
    ad_username: str = ""
    ad_password: str = ""
    ad_ou: str = ""
    disabled_users_ou: str = ""  # OU where disabled users are stored (e.g., "OU=Disabled Users,DC=example,DC=com")
    db_url: str = "postgresql+psycopg2://user:password@postgres-service:5432/userdb"
    secret_key: str = "change_me"

    # Admin configuration
    admin_username: str = "admin"
    admin_password: str = "adminpass"
    
    # Admin OUs configuration (comma-separated list of OUs that have admin access)
    admin_ous: List[str] = []  # Example: ["OU=IT Admins,DC=example,DC=com", "OU=Security,DC=example,DC=com"]
    admin_groups: List[str] = []  # Example: ["CN=IT Admins,OU=Groups,DC=example,DC=com"]

    class Config:
        env_file = ".env"

settings = Settings()
