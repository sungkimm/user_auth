from fastapi import APIRouter, Depends

from layer import refresh_access_token, issue_new_access_token, create_new_tokens
from dependencies import validate_access_token, validate_refresh_token


router = APIRouter(
    prefix="/api/token",
    tags=["token"]
)


@router.post('/create_tokens')
def create_tokens_testcase():
    access, refresh = create_new_tokens()

    return {"access_token" : access, 
            "refresh_token" : refresh }


@router.post('/create_token_with_userinfo')
def add_user_info_to_token(access_token : str = Depends(validate_access_token)):
    
    tmp = issue_new_access_token(access_token)
    has_changed = not(tmp == access_token)
    access_token = tmp
    print('Access token includes user info now')
    
    return {"access_token" : access_token,
            "has_token_changed" : has_changed}



@router.post('/refresh')
def refresh_tokens(access_token : str = Depends(validate_access_token),
                refresh_token : str = Depends(validate_refresh_token)):


    new_access_token, new_fresh_token = refresh_access_token(access_token, refresh_token)

    rst = {
            'has_access_changed': not(access_token==new_access_token),
            'has_refresh_changed': not(refresh_token==new_fresh_token),
            'access_token':new_access_token, 
            'refresh_token': new_fresh_token}


    return rst






@router.get('/login')
def login():

    print('logiiinnng')
    return {'y':'y'}