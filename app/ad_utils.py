from ldap3 import Server, Connection, Tls, ALL
import ssl
from .config import settings

def get_ad_connection(server_url, cert_path, username, password):
    tls = Tls(local_private_key_file=None, local_certificate_file=cert_path, validate=ssl.CERT_REQUIRED)
    server = Server(server_url, use_ssl=True, get_info=ALL, tls=tls)
    conn = Connection(server, user=username, password=password, auto_bind=True)
    return conn

# Add more AD utility functions as needed

def unlock_ad_account(ad_account_id: str):
    """
    Unlocks an Active Directory account given the sAMAccountName (ad_account_id).
    """
    conn = get_ad_connection(
        settings.AD_SERVER_URL,
        settings.AD_CERT_PATH,
        settings.AD_USERNAME,
        settings.AD_PASSWORD
    )
    # Search for the user DN
    search_base = settings.AD_SEARCH_BASE
    search_filter = f"(sAMAccountName={ad_account_id})"
    conn.search(search_base, search_filter, attributes=["distinguishedName"])
    if not conn.entries:
        raise ValueError(f"Account '{ad_account_id}' not found in AD.")
    user_dn = conn.entries[0].distinguishedName.value
    # Unlock the account using Microsoft extension
    conn.extend.microsoft.unlock_account(user_dn)
    conn.unbind()
