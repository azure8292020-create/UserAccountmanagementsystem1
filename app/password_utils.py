import random
import string
from typing import Tuple

def generate_complex_password(length: int = 16) -> str:
    """Generate a complex password meeting requirements:
    - 16 characters long
    - Include numbers, uppercase, lowercase, and special characters
    - No four continuous characters of the same kind
    """
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|"
    
    def get_different_type(prev_types):
        """Get a character of a different type than the last three."""
        if len(set(prev_types[-3:])) == 1:  # If last 3 are same type
            available_types = [t for t in ['lower', 'upper', 'digit', 'symbol'] if t != prev_types[-1]]
            chosen_type = random.choice(available_types)
        else:
            chosen_type = random.choice(['lower', 'upper', 'digit', 'symbol'])
        
        if chosen_type == 'lower':
            return random.choice(lowercase), 'lower'
        elif chosen_type == 'upper':
            return random.choice(uppercase), 'upper'
        elif chosen_type == 'digit':
            return random.choice(digits), 'digit'
        else:
            return random.choice(symbols), 'symbol'

    # Initialize with one of each required type
    password = []
    char_types = []
    
    # Build password ensuring no 4 consecutive same types
    while len(password) < length:
        char, char_type = get_different_type(char_types)
        password.append(char)
        char_types.append(char_type)
    
    # Ensure at least one of each type exists
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in symbols for c in password)
    
    # If missing any required type, replace random positions
    if not has_lower:
        password[random.randint(0, length-1)] = random.choice(lowercase)
    if not has_upper:
        password[random.randint(0, length-1)] = random.choice(uppercase)
    if not has_digit:
        password[random.randint(0, length-1)] = random.choice(digits)
    if not has_symbol:
        password[random.randint(0, length-1)] = random.choice(symbols)
    
    return ''.join(password)

def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """Validate password meets complexity requirements."""
    if len(password) != 16:
        return False, "Password must be exactly 16 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letters"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"
    
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain special characters"
    
    # Check for four continuous characters of the same kind
    def has_four_continuous(s, char_type):
        count = 0
        for c in s:
            if char_type(c):
                count += 1
                if count >= 4:
                    return True
            else:
                count = 0
        return False
    
    if has_four_continuous(password, str.isupper):
        return False, "Password cannot have 4 continuous uppercase letters"
    
    if has_four_continuous(password, str.islower):
        return False, "Password cannot have 4 continuous lowercase letters"
    
    if has_four_continuous(password, str.isdigit):
        return False, "Password cannot have 4 continuous numbers"
    
    return True, "Password meets complexity requirements"