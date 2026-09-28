from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
from google.oauth2 import id_token
from google.auth.transport import requests
from app.core.config import settings

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        # Use google-auth directly to verify the Firebase ID token without requiring ADC (Application Default Credentials)
        request = requests.Request()
        decoded_token = id_token.verify_firebase_token(
            token, 
            request, 
            audience=settings.GOOGLE_CLOUD_PROJECT
        )
        return decoded_token
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication token")

