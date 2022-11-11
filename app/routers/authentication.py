from fastapi import APIRouter, Depends
from pydantic import BaseModel

from layer import logout
from dependencies import validate_access_token, get_valid_user_info


router = APIRouter(
    prefix="/api/auth",
    tags=["Authenication"],
    dependencies=[Depends(validate_access_token)]
)


class UserInfo(BaseModel):
    userid: str
    user_role: str


@router.post('/logout')
def user_logout():
    logout()
    # raise HTTPException()
    return {'logout' : True}


@router.post('/authentication')
def token_authentication(access_token : str = Depends(validate_access_token)):

    return {'is_validated' : True, 
            'acess_token': access_token}

# ------------------ Authroization 
@router.post('/get_valid_user_info')
def valid_user_info(user : UserInfo = Depends(get_valid_user_info)):

    return user

