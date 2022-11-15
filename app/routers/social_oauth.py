from fastapi import APIRouter, Depends
import httpx
from config import social_oauth_cfg
import user_logic
from layer import create_new_tokens

kakao_cfg = social_oauth_cfg['kakao']

router = APIRouter(
    prefix="/api/oauth",
    tags=["social OAuth2.0"]
)


@router.get('/facebook/callback')
def facebook_callback():

    response = httpx.post(kakao_cfg['auth_code_url'], data=data, headers=headers)

    return {'y':'y'}




@router.get('/kakao/callback')
async def facebook_callback(code : str, state: str = '', error : str = '', error_description : str = ''):

    data = {"grant_type" : kakao_cfg['grant_type'],
            "client_id" : kakao_cfg['client_id'],
            "code" : code,
            "redirect_url" : kakao_cfg['redirect_url'],
            "client_secret" : kakao_cfg['client_secret']
            }
    headers = {"Content-type" : "application/x-www-form-urlencoded;charset=utf-8"}

    
    # TODO: async with context manager(with)
    response = httpx.post(kakao_cfg['auth_code_url'], data=data, headers=headers)
    
    
    print(response.json())

    #     {'access_token': '',
    #  'token_type': 'bearer', 
    #  'refresh_token': '',
    #   'id_token': '', 
    #   'expires_in': 21599, 
    #   'scope': 'age_range account_email openid profile_nickname', 
    #   'refresh_token_expires_in': 5183999}

    # error 302

    return response.json()



    # if response.status_code == 200:

    #     # check if user has an account
    #     if not user_logic.is_user_exist(): 
    #         # user sign up
    #         user_logic.user_sign_up()
        

    #     # login

    #     # token issue

        

    #     return {"access_token" : access, 
    #             "refresh_token" : refresh }
            

    # else:
    #     raise 