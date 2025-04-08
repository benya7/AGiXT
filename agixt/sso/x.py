import requests
import logging
from fastapi import HTTPException
from Globals import getenv

"""
Required environment variables:

- X_CLIENT_ID: X OAuth client ID
- X_CLIENT_SECRET: X OAuth client secret

Required scopes for Twitter OAuth:
"""

SCOPES = [
    "tweet.read",
    "tweet.write",
    "users.read",
    "offline.access",
    "like.read",
    "like.write",
    "follows.read",
    "follows.write",
    "dm.read",
    "dm.write",
]
AUTHORIZE = "https://x.com/i/oauth2/authorize"
PKCE_REQUIRED = True


class XSSO:
    def __init__(
        self,
        access_token=None,
        refresh_token=None,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client_id = getenv("X_CLIENT_ID")
        self.client_secret = getenv("X_CLIENT_SECRET")
        self.user_info = None
        if self.access_token:
            self.user_info = self.get_user_info()

    def get_new_token(self):
        response = requests.post(
            "https://api.x.com/2/oauth2/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
                "scope": " ".join(SCOPES),
            },
        )
        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")
        return response.json()["access_token"]

    def get_user_info(self):
        """
        Retrieve user information from X API with enhanced error handling and logging.
        
        Returns:
            Dict containing email, first_name, and last_name of the user
            
        Raises:
            HTTPException: If the API request or data processing fails
        """
        uri = "https://api.x.com/2/users/me?user.fields=name,username,profile_image_url,confirmed_email"
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        try:
            # Initial API request
            response = requests.get(
                uri,
                headers={"Authorization": f"Bearer {self.access_token}"},
                timeout=10  # Add timeout to prevent hanging
            )
            
            # Handle authentication failure
            if response.status_code == 401:
                logger.info("Access token expired, attempting to refresh")
                self.access_token = self.get_new_token()
                response = requests.get(
                    uri,
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=10
                )
            
            # Check for other HTTP errors
            response.raise_for_status()
            
            # Parse JSON response
            try:
                data = response.json()
                logger.debug(f"Received response: {data}")
                
                # Check if 'data' key exists in response
                if "data" not in data:
                    logger.error(f"Invalid API response format: {data}")
                    raise HTTPException(
                        status_code=502,
                        detail="Invalid response format from X API"
                    )
                    
                user_data = data["data"]
                
                # Validate required fields
                required_fields = ["name", "confirmed_email"]
                missing_fields = [field for field in required_fields if field not in user_data]
                if missing_fields:
                    logger.error(f"Missing required fields: {missing_fields}")
                    raise HTTPException(
                        status_code=502,
                        detail=f"Missing required fields from X API: {missing_fields}"
                    )
                    
                # Process name
                full_name = user_data["name"]
                name_parts = full_name.split(" ", 1)
                first_name = name_parts[0].strip()
                last_name = name_parts[1].strip() if len(name_parts) > 1 else ""
                
                return {
                    "email": user_data["confirmed_email"],
                    "first_name": first_name,
                    "last_name": last_name,
                }
                
            except ValueError as ve:
                logger.error(f"Failed to parse JSON response: {str(ve)}")
                raise HTTPException(
                    status_code=502,
                    detail="Invalid JSON response from X API"
                )
                
        except requests.Timeout:
            logger.error("Request to X API timed out")
            raise HTTPException(
                status_code=504,
                detail="X API request timed out"
            )
            
        except requests.RequestException as re:
            logger.error(f"API request failed: {str(re)}")
            raise HTTPException(
                status_code=503,
                detail=f"Failed to connect to X API: {str(re)}"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error in get_user_info: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail="Internal server error while processing X user info"
            )


def sso(code, redirect_uri=None, code_verifier=None) -> XSSO:
    if not redirect_uri:
        redirect_uri = getenv("APP_URI")
    code = (
        str(code)
        .replace("%2F", "/")
        .replace("%3D", "=")
        .replace("%3F", "?")
        .replace("%3D", "=")
    )
    client_id = getenv("X_CLIENT_ID")
    client_secret = getenv("X_CLIENT_SECRET")
    response = requests.post(
        "https://api.x.com/2/oauth2/token",
        data={
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        },
        auth=(client_id, client_secret),
    )
    if response.status_code != 200:
        logging.error(f"Error getting X access token: {response.text}")
        return None
    data = response.json()
    access_token = data["access_token"]
    refresh_token = data["refresh_token"] if "refresh_token" in data else None
    return XSSO(access_token=access_token, refresh_token=refresh_token)
