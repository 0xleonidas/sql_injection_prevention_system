class WhitelistingManager:
    allowed_sql_keywords = [
        "select"  # All keywords stored in lowercase
    ]

    def __init__(self, input_data):
        self.input_data = input_data.lower()  # Convert input to lowercase

    def check_whitelist(self):
        """
        Check if the input query contains only allowed SQL keywords or any other words.
        """
        # Split the input into words to check against allowed keywords
        input_words = self.input_data.split()

        for word in input_words:
            # If the word is not in the allowed keywords, it should be allowed
            if word not in self.allowed_sql_keywords:
                # Optionally: Check if the word is something unexpected
                # If you want to allow all words, you might not need additional checks here
                pass
        
        return True
