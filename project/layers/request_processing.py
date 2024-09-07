from werkzeug.security import check_password_hash
from sqlalchemy import text
from sqlalchemy.engine import Result

class RequestProcessingLayer:
    
    def __init__(self, db_session):
        self.db_session = db_session

    def execute_query(self, query, params=None):
        """
        Safely executes a parameterized query with the given parameters.
        """
        try:
            sql_query = text(query)  # Wrap query in text()
            if params:
                result = self.db_session.execute(sql_query, params)
            else:
                result = self.db_session.execute(sql_query)
            
            # Convert result to a list of dictionaries
            if isinstance(result, Result):
                fetched_result = [dict(row) for row in result.mappings()]
            else:
                fetched_result = [dict(row) for row in result]
            
            print(f"Query executed. Results: {fetched_result}")  # Debugging output
            return fetched_result
            
        except Exception as e:
            print(f"Query execution error: {e}")  # Debugging output
            raise ValueError("An error occurred while processing the request.") from e

    def process_login(self, username, password):
        """
        Example method to process login requests using parameterized queries.
        """
        query = "SELECT id, username, password FROM user WHERE username = :username"
        params = {"username": username}

        try:
            result = self.execute_query(query, params)
            
            if result:
                # Assuming the result is a list of dictionaries where each dictionary represents a row
                user = result[0]  # Get the first row
                
                # Access columns by name
                user_id = user['id']
                stored_username = user['username']
                stored_password = user['password']
                
                if check_password_hash(stored_password, password):  # Check password hash
                    return {"id": user_id, "username": stored_username}  # Return user details in dictionary format
                else:
                    raise ValueError("Invalid username or password.")
            else:
                raise ValueError("Invalid username or password.")
                
        except ValueError as e:
            raise ValueError("Error during login.") from e
