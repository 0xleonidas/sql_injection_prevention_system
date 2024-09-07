import re

class SanitizationManager:
    sql_keywords = [
        "INSERT", "UPDATE", "SELECT", "AND", "OR", "DELETE", "DROP", "ALTER", "CREATE", "EXECUTE",
        "MERGE", "REPLACE", "UNION", "WHERE", "JOIN", "--", ";", "'", "\"",
        "=", "<", ">", "!", "LIKE", "BETWEEN", "IN", "IS", "NULL", "NOT", "HAVING",
        "GROUP BY", "ORDER BY", "LIMIT", "OFFSET", "DISTINCT", "CAST", "CONVERT", "TRUNCATE",
        "TRIGGER", "INDEX", "VIEW", "TABLE", "DATABASE", "GRANT", "REVOKE", "COMMIT", "ROLLBACK"
    ]

    def __init__(self, input_data, is_sensitive=False):
        self.input_data = input_data
        self.is_sensitive = is_sensitive

    def detect_sql_injection(self):
        """
        Detects SQL injection patterns based on SQL keywords and suspicious characters.
        """
        input_upper = self.input_data.upper()

        # Check for SQL keywords or patterns
        for keyword in self.sql_keywords:
            # Check if the keyword is a substring within the input data
            if re.search(r'(\W|^)' + re.escape(keyword) + r'(\W|$)', input_upper):
                raise ValueError(f"SQL injection detected: {keyword} keyword or pattern found.")

        # Check for suspicious characters if sensitive
        if self.is_sensitive:
            if re.search(r"[;\'\"--]+", self.input_data):
                raise ValueError("SQL injection detected: Suspicious characters found.")
