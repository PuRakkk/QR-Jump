import time
import datetime
import jwt  # Install with `pip install pyjwt` if not installed
from jwt import ExpiredSignatureError, DecodeError

# Sample token (Replace with your actual token)
ACCESS_TOKEN = """
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzM3NDM4MzUzLCJpYXQiOjE3Mzc0MzgyMzMsImp0aSI6IjVmOTg0ZDkzNzg2MTRkMzFiMDA3Y2M5NGMyZmNlNjVmIiwidXNlcl9pZCI6MX0.IhMtCbpm_fCF_eoApIjH7IsmE79H3CVj8CnPXtX0PvQ
"""

# Secret key used for encoding/decoding (Only needed for signature verification)
SECRET_KEY = "your-secret-key"

def check_access_token(token):
    try:
        # Decode the token without verifying the signature
        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
        
        # Extract relevant claims
        token_type = payload.get("token_type")
        expiration_time = payload.get("exp")
        issued_at = payload.get("iat")
        user_id = payload.get("user_id")
        jti = payload.get("jti")

        # Check if required claims are present
        if not all([token_type, expiration_time, issued_at, user_id, jti]):
            return "Token is invalid: Missing required claims."

        # Get the current time
        current_time = int(time.time())

        # Check expiration
        if current_time >= expiration_time:
            expired_at = datetime.datetime.utcfromtimestamp(expiration_time).strftime('%Y-%m-%d %H:%M:%S UTC')
            return f"Token has expired. Expired at {expired_at}."
        else:
            remaining_time = expiration_time - current_time
            expires_in = str(datetime.timedelta(seconds=remaining_time))
            return f"Token is valid. Expires in {expires_in}."

    except DecodeError:
        return "Token is invalid: Unable to decode."
    except ExpiredSignatureError:
        return "Token is invalid: Signature has expired."
    except Exception as e:
        return f"An error occurred: {str(e)}"

# Main function
if __name__ == "__main__":
    # Call the check function and display the result
    result = check_access_token(ACCESS_TOKEN.strip())
    print(result)
