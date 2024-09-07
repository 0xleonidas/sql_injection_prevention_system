import re

class IntegrityCheckManager:
    
    def __init__(self, data):
        self.data = data
    
    def check_username_length(self):
        """
        Check if the username length is within acceptable limits.
        """
        username = self.data.get("username")
        if len(username) < 5 or len(username) > 20:
            raise ValueError("Username must be between 5 and 20 characters.")
        return True
    
    def check_password_strength(self):
        """
        Check if the password meets minimum strength requirements.
        """
        password = self.data.get("password")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one number.")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter.")
        return True
    
    def run_integrity_checks(self):
        """
        Run all integrity checks for the data.
        """
        self.check_username_length()
        self.check_password_strength()
        return True
