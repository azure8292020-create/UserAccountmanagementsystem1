from ldap3 import Server, Connection, Tls, ALL
import ssl
from typing import Optional, Tuple
from .config import settings

def get_ad_connection(server_url: str, cert_path: str, username: str, password: str) -> Connection:
    """Create a connection to an AD server."""
    tls = Tls(
        validate=ssl.CERT_NONE,  # Disable certificate validation temporarily
        version=ssl.PROTOCOL_TLS_CLIENT
    )
    server = Server(
        server_url, 
        use_ssl=True, 
        get_info=ALL, 
        tls=tls,
        connect_timeout=5
    )
    conn = Connection(
        server, 
        user=username, 
        password=password, 
        auto_bind=True,
        authentication='SIMPLE'
    )
    return conn

def get_available_ad_connection() -> Tuple[Optional[Connection], Optional[str]]:
    """Try to connect to each AD server in order until one succeeds."""
    last_error = None
    for server, cert in zip(settings.ad_servers, settings.ad_certs):
        try:
            conn = get_ad_connection(server, cert, settings.ad_username, settings.ad_password)
            return conn, None
        except Exception as e:
            last_error = str(e)
            continue
    return None, last_error

def unlock_ad_account(ad_account_id: str):
    """Unlocks an Active Directory account, trying all available AD servers."""
    conn, error = get_available_ad_connection()
    if not conn:
        raise ValueError(f"Could not connect to any AD server: {error}")

    try:
        # Search for the user DN
        search_base = settings.ad_ou
        search_filter = f"(sAMAccountName={ad_account_id})"
        conn.search(search_base, search_filter, attributes=["distinguishedName"])
        if not conn.entries:
            raise ValueError(f"Account '{ad_account_id}' not found in AD.")
        
        user_dn = conn.entries[0].distinguishedName.value
        # Unlock the account using Microsoft extension
        conn.extend.microsoft.unlock_account(user_dn)
    finally:
        conn.unbind()

def check_ad_health() -> Tuple[bool, str]:
    """Check health of AD servers and return status."""
    all_statuses = []
    any_success = False

    for i, (server, cert) in enumerate(zip(settings.ad_servers, settings.ad_certs), 1):
        try:
            conn = get_ad_connection(server, cert, settings.ad_username, settings.ad_password)
            # Try a simple search
            search_base = settings.ad_ou
            search_filter = "(objectClass=user)"
            conn.search(search_base, search_filter, attributes=['sAMAccountName'], size_limit=1)
            if conn.entries:
                all_statuses.append(f"AD Server {i}: Connected and found user entries")
                any_success = True
            else:
                all_statuses.append(f"AD Server {i}: Connected but no user entries found")
            conn.unbind()
        except Exception as e:
            all_statuses.append(f"AD Server {i}: Connection failed - {str(e)}")

    status_message = " | ".join(all_statuses)
    return any_success, status_message

def find_user_in_ad(ad_account_id: str) -> bool:
    """Search for a user across all AD servers."""
    for server, cert in zip(settings.ad_servers, settings.ad_certs):
        try:
            conn = get_ad_connection(server, cert, settings.ad_username, settings.ad_password)
            search_base = settings.ad_ou
            search_filter = f"(sAMAccountName={ad_account_id})"
            conn.search(search_base, search_filter, attributes=['sAMAccountName'])
            conn.unbind()
            if conn.entries:
                return True
        except Exception:
            continue
    return False

def reset_ad_password(ad_account_id: str, new_password: str) -> Tuple[bool, str]:
    """Reset user's password and set change password at next logon."""
    conn, error = get_available_ad_connection()
    if not conn:
        return False, f"Could not connect to any AD server: {error}"

    try:
        # Search for the user DN
        search_base = settings.ad_ou
        search_filter = f"(sAMAccountName={ad_account_id})"
        conn.search(search_base, search_filter, attributes=["distinguishedName"])
        
        if not conn.entries:
            return False, f"Account '{ad_account_id}' not found in AD."
        
        user_dn = conn.entries[0].distinguishedName.value
        
        # Reset password
        conn.extend.microsoft.modify_password(user_dn, new_password)
        
        # Set "Change password at next logon"
        conn.modify(user_dn,
            {'pwdLastSet': [('MODIFY_REPLACE', [0])]})
        
        return True, "Password reset successfully"
    except Exception as e:
        return False, f"Failed to reset password: {str(e)}"
    finally:
        conn.unbind()
