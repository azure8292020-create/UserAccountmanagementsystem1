from ldap3 import Server, Connection, Tls, ALL
import logging
import time
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

def is_user_disabled(username: str) -> Tuple[bool, str]:
    """Check if a user is in the disabled users OU."""
    if not settings.disabled_users_ou:
        return False, "Disabled users OU not configured"

    conn, error = get_available_ad_connection()
    if not conn:
        return False, f"Could not connect to AD: {error}"

    try:
        # Search for the user in the disabled users OU
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        conn.search(settings.disabled_users_ou, search_filter, attributes=['distinguishedName'])
        
        # If user is found in disabled OU, they are disabled
        if conn.entries:
            return True, "User account is in disabled users OU"
        
        return False, "User is not in disabled users OU"
    except Exception as e:
        logging.error(f"Error checking disabled status: {str(e)}")
        return False, f"Error checking disabled status: {str(e)}"
    finally:
        conn.unbind()

def check_account_status(username: str) -> dict:
    """Check if an AD account is locked, disabled, or expired."""
    conn, error = get_available_ad_connection()
    if not conn:
        return {"success": False, "error": f"Could not connect to AD: {error}"}

    try:
        search_base = settings.ad_ou
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        attributes = ['lockoutTime', 'userAccountControl', 'accountExpires']
        
        conn.search(search_base, search_filter, attributes=attributes)
        if not conn.entries:
            return {"success": False, "error": "User not found"}
            
        user = conn.entries[0]
        
        # Check if account is locked
        is_locked = int(user.lockoutTime.value or 0) > 0
        
        # Check if account is disabled
        uac = int(user.userAccountControl.value or 0)
        is_disabled = bool(uac & 2)  # 2 is USER_ACCOUNT_DISABLED
        
        # Check if account is expired
        account_expires = int(user.accountExpires.value or 0)
        is_expired = account_expires != 0 and account_expires < (int(time.time()) * 10000000 + 116444736000000000)
        
        return {
            "success": True,
            "status": {
                "is_locked": is_locked,
                "is_disabled": is_disabled,
                "is_expired": is_expired
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.unbind()

def get_user_info_from_ad(conn: Connection, username: str) -> Optional[dict]:
    """Fetch user information from Active Directory.
    Returns a dictionary containing user details or None if user not found."""
    try:
        search_base = settings.ad_ou
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        attributes = ['givenName', 'sn', 'middleName', 'displayName', 'mail', 'sAMAccountName']
        
        conn.search(search_base, search_filter, attributes=attributes)
        
        if not conn.entries:
            return None
            
        user = conn.entries[0]
        
        user_info = {
            "first_name": user.givenName.value if hasattr(user, 'givenName') else "",
            "last_name": user.sn.value if hasattr(user, 'sn') else "",
            "middle_name": user.middleName.value if hasattr(user, 'middleName') else "",
            "display_name": user.displayName.value if hasattr(user, 'displayName') else "",
            "email": user.mail.value if hasattr(user, 'mail') else "",
            "username": user.sAMAccountName.value if hasattr(user, 'sAMAccountName') else ""
        }
        
        return user_info
    except Exception as e:
        logging.error(f"Error fetching AD user info: {str(e)}")
        return None

def validate_ad_credentials(username: str, password: str) -> bool:
    """Validate Active Directory credentials by attempting to bind with provided credentials."""
    try:
        for server, cert in zip(settings.ad_servers, settings.ad_certs):
            try:
                # Try to bind with user credentials
                conn = get_ad_connection(server, cert, username, password)
                conn.unbind()
                return True
            except Exception:
                continue
        return False
    except Exception as e:
        logging.error(f"AD credential validation error: {str(e)}")
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
