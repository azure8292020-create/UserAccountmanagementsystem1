from typing import Tuple
from .config import settings
from .ad_utils import get_ad_connection

def check_user_admin_access(username: str) -> Tuple[bool, str]:
    """
    Check if a user has admin access based on their AD group memberships and OU placement
    
    Args:
        username: The AD username to check
        
    Returns:
        Tuple[bool, str]: (has_access, reason)
    """
    try:
        # Try connecting to each AD server
        for server, cert in zip(settings.ad_servers, settings.ad_certs):
            try:
                conn = get_ad_connection(server, cert, settings.ad_username, settings.ad_password)
                
                # Find user DN first
                search_filter = f"(sAMAccountName={username})"
                conn.search(settings.ad_ou, search_filter, attributes=['distinguishedName', 'memberOf'])
                
                if not conn.entries:
                    continue  # User not found in this server, try next one
                
                user_entry = conn.entries[0]
                user_dn = str(user_entry.distinguishedName)
                
                # Check if user is in admin OUs
                for admin_ou in settings.admin_ous:
                    if admin_ou.lower() in user_dn.lower():
                        return True, "User belongs to admin OU"
                
                # Check admin group membership
                if hasattr(user_entry, 'memberOf'):
                    member_of = [str(group) for group in user_entry.memberOf]
                    for admin_group in settings.admin_groups:
                        if admin_group.lower() in [group.lower() for group in member_of]:
                            return True, "User belongs to admin group"
                
            except Exception as e:
                continue  # Try next server on error
    
    except Exception as e:
        return False, f"Error checking admin access: {str(e)}"
    
    return False, "User does not have admin privileges"