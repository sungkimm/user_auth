from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from pydantic import BaseModel
from typing import Tuple

from layer import authenticate_token, access_token_encrypter, refresh_token_encrypter
from jwt_token import JWTTokenEncrypter


security = HTTPBearer()


# TODO: move this class
class UserInfo(BaseModel):
    userid: str
    user_role: str
    access_token: str


def validate_access_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    '''
    Token authentication 
    Access Token must be included on header with Authorization key and bear type
    '''

    access_token = credentials.credentials
    authenticate_token(access_token_encrypter, access_token)
    
    return access_token



def validate_refresh_token(refresh_token = Depends(APIKeyHeader(name='refresh_token'))):
    '''
    Token authentication 
    Refresh Token must be included on header with refresh_token key and bear type
    '''
    
    authenticate_token(refresh_token_encrypter, refresh_token)
    return refresh_token



def decode_access_token(credentials: HTTPAuthorizationCredentials = Security(security)):

    access_token = credentials.credentials
    
    return authenticate_token(access_token_encrypter, access_token), access_token # return payload, header, access_token



def validate_both_tokens( access_token : str = Depends(validate_access_token), 
                          refresh_token : str = Depends(validate_refresh_token)):
    
    if not (access_token or refresh_token):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return access_token, refresh_token






# ------------------ Authroization 
def get_valid_user_info(access : Tuple[dict, dict] = Depends(decode_access_token)):

    try:
        jwt_data, access_token = access
        payload, _ = jwt_data

        attributes = { "userid": payload['userID'], 
                    "user_role": payload['role'], 
                    "access_token" : access_token
                    }
    except KeyError as e:

        raise HTTPException(status_code=401, detail="{} not defined in token".format(e))


    return UserInfo(**attributes)