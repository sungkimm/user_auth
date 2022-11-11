from fastapi import HTTPException
from datetime import datetime, timezone
from functools import partial

import jwt
from jwt_token import JWTTokenEncrypter


access_cfg_path = 'config/access_token_cfg.yml'
access_token_encrypter = JWTTokenEncrypter(access_cfg_path)

refresh_cfg_path = 'config/refresh_token_cfg.yml'
refresh_token_encrypter = JWTTokenEncrypter(refresh_cfg_path)


def jwt_error_handler(func):
    
    def inner_function(*args, **kwargs):
        
        http_exception = partial(HTTPException, status_code=401, headers={"WWW-Authenticate": "Bearer"})

        try:
            results = func(*args, **kwargs)
        
        except jwt.exceptions.InvalidIssuerError as e:
            raise http_exception(detail='Invalid Issuer')
        except jwt.ExpiredSignatureError as e:
            raise http_exception(detail='Token Expired')
        except jwt.exceptions.InvalidAlgorithmError as e:
            raise http_exception(detail='Invalid Algorithms')
        except jwt.exceptions.InvalidSignatureError as e: # when signature doesn't match the one provided
            raise http_exception(detail='Invalid Signature')
        except jwt.exceptions.DecodeError as e:
            raise http_exception(detail='Invalid Header')
        except jwt.exceptions.MissingRequiredClaimError as e:
            raise http_exception(detail='Missing Required Claims')
        except jwt.exceptions.InvalidTokenError as e:
            raise http_exception(detail='Invalid Token')
        except TypeError as e:
            print(str(e))
            raise http_exception(detail='Invalid Token')
        
        # Do Not handle Exception case
        
        return results

    return inner_function


def callback_url():
    # request access token with auth code

    # save meta data's to db

    # save tokens

    # login then

    pass



def create_new_tokens():

    payload = access_token_encrypter.create_payload()
    access_token = access_token_encrypter.encode_token(payload)

    payload = refresh_token_encrypter.create_payload()
    refresh_token = refresh_token_encrypter.encode_token(payload)


    return access_token, refresh_token


def logout():
    # Delete refresh and access toekn
    print("logging out!!")
    raise HTTPException(status_code=201, detail="logging out")




@jwt_error_handler
def authenticate_token(encrypter, token):
    
    payload, header, _ = encrypter.decode_token(token)

    return payload, header



def issue_new_access_token(access_token):

    payload, header = authenticate_token(access_token_encrypter, access_token)

    payload['userID'] = 'ss1r2d32dw5wr3'
    payload['role'] = 'admin'

    new_access_token = access_token_encrypter.encode_token(payload)
    
    # print(access_token_encrypter.decode_token(new_access_token))

    return new_access_token



def is_access_regen(access_token_from_clinet):

    def get_latest_access_key_testcase():

        with open("token_db.txt", "r") as r:
            keys = r.readlines()
            latest_key = keys[-1].strip()
        
        return latest_key

    # query the most recent access-token from DB
    latest_access_token = get_latest_access_key_testcase()

    return not(access_token_from_clinet == latest_access_token)





@jwt_error_handler
def refresh_access_token(access_token, refresh_token):

    try:
        refresh_token_encrypter.decode_token(refresh_token)
    except jwt.ExpiredSignatureError as e:
        print("Refresh token expired..")
        logout()


    try:
        # TODO: get user info from DB
        access_token_encrypter.decode_token(access_token)


        print("Valid Access Token.. returning them back")

    except jwt.ExpiredSignatureError as e: # if access-token is expired

        print('Access Expried')

        if not is_access_regen(access_token):  
            
            # create new tokens
            access_payload = access_token_encrypter.create_payload()
            new_access_token = access_token_encrypter.encode_token(access_payload)

            refresh_payload = refresh_token_encrypter.create_payload()
            new_refresh_token = refresh_token_encrypter.encode_token(refresh_payload)


            ############### Test case
            # ac_h, _,_ = access_token_encrypter.decode_token(new_access_token)
            # re_h, _,_ = refresh_token_encrypter.decode_token(new_refresh_token)
            print("Created new aceess token..")
            
            a_e = access_payload['exp'].replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H')
            a_i = access_payload['iat'].replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H')
            # r_e = refresh_payload['exp'].replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H')
            # r_i = refresh_payload['iat'].replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H')

            print("New Acesss Token: issued at {} | exp at {}".format(a_i, a_e))
            print("Returning the same refresh token")
            # print("New Refresh Token: issued at {} | exp at {}".format(r_i, r_e))

            # save the new ones to DB


            return new_access_token, refresh_token

        else:
            print("Latest access token saved in DB and token from client do not match")
            logout()
    

    return access_token, refresh_token



# @jwt_error_handler
def authentication_test():

    # Test authentication
    payload = access_token_encrypter.create_payload()
    access_token = access_token_encrypter.encode_token(payload)
    new_token = issue_new_access_token(access_token)
    print(new_token)



def test():

    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjM3NjY4MDgzMDA5LCJpc3MiOiJhc2RhZGFzZGEiLCJpYXQiOjE2NjgwODY2MDl9.ToaSGQ1wHVCFYj0pOy1waCLOzx8fQr-sN9YzcinwAj7FuS0O5Vgqc89rIwLZwqnDdONBhM0iN2eZmacOkknMQSDo_QdfhswYPkTelbqKgpdhFP14kBbEnHpHjV-29mVe5ipyM3nuaVGsBgK75oReuoqlu2AGyrIlNWwmqS59d7PuaGyphLouZIOkd2wNFp2BTKJOr6F7znAr29m0jIixMBQi4OtPtmdxr624IPpSJcUojFfzzVcMpymD8hG60qfb--P-2olMbE8sF6fxUhQ524XdG9Ij0e6j36V_mkwThVWpfuJv66LzE_5tSwqoZPkgIcDG-HKPxiIv7v8ZjXMWmni4-bhp9PoMuqqlexvKhufc0AgXs80X-iwz4GqAaCwKwCkiphnPXx3vOMddDi0ZN4qDYrLr5D2DJnDbXMGZGciWw_ocO04dzaFkGcPIKlrmEeQ9NhlZpTvGtDXW1UK7gTaY7SLza_H2Jmz4Da0DMdUZoTW6jgdPELk45E0Uk-Z5"
    # new = issue_new_access_token(token)
    # print(new)
    a,b = authenticate_token(access_token_encrypter, token)
    print(a,b)


def refresh_tokens_test():
    

    # val token (+hours 9999999)
    access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjM3NjY3NzIxNTcxLCJpc3MiOiJhY2Nlc3NfaXNzdWUiLCJpYXQiOjE2Njc3MjUxNzF9.iWkIZjJtQzJTpj1HO17qnGkMBm5aQJhnz1beZK5-47cqjNojJo-asKs1tS1q2awTyCbc-4FG8s3V7F5oJt0W3Ak_QDhsxAi5JPC_9RZ2vllj5HIWTcRgmR4_786mXn-DfzbJufGVDT-MmIaXcikKDunMOGikLnnkxKNdW-EFZsflxkrgCjsY0s4OguCe-m1gEu8N76jitsSWoFaFYbWE_XBX58Ozb3rwhG7dlB0TXed1uGEP05hLrQedyWPsziJJzBYLrFzSPA6lkfs9Jl3BXnanoc-hpJYy2Vn5OrLI0e6U0rZjnk6wWffVp6y2sLKuawkVvq8dPYkvhbDCnInur-K_wtJboA4AmCrEuVND2Ca0KZzqr8_f7p4FrCO_oqi93KIuYdnqQeCbHQhudkUHbGe8WLuoy9-5KAX2ywJswu-lHhokyYe2p8Hhr1xc3lgp67QOgLnQg_lYrXgZTZxMgg8XbetQiULmXeGeE5pztwLRPTkTbrmx4yJDb2U5UxSD"
    refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjM3NjY3NzIxNTcxLCJpc3MiOiJyZWZyZXNoX2lzc3VlIiwiaWF0IjoxNjY3NzI1MTcxfQ.iRyJcKjhO3I9YPfhFVdJj2PSqzc-d6MVotUtW_r2TTDMJoLG8OO1XigmiP9qIv5FlYovV3lrVcoHLOrocyEwUOPRIVZsfmy_9ON9uyP0weLNPGDS4pEafIh1Q5Wg8PeVtUd8FHcWfyMYxsHR1NwgUkG-brBn0P6TcegE-LxILGzVq490oL4tRUZuTq6kYSjlYsHZyt_MmKRUcx-hQUFF2TlZ3cupEwJ20nhx5NgrF0UsZMUsu7m48mQkR_zBv0tqfmFyF_Aavl9SqYss-Gwk1NZm12cjhBmfQj8sTjDJQpn5k7R2Pg-p_snb6Mx4i4PDtBf75BjI_oTTkyeJDlCx48hbmZQFCBETJoajOC7ySRT8EpAbudJQBH4ONwzFDFPmzd5RHUfRas7ikFRy60Ew6rb2OgMXFKFElq8QDfCk2dG4ND8vjSRqeQWKgiFDmWMocLQWqvY2EMXDPlXt_pJhusQhdhCakX8YdvD4O21mT6MLwgMmKLm1pZtR7LavJcq1"

    # expired token
    old_access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2Njc3MjA0NjQsImlzcyI6ImFjY2Vzc19pc3N1ZSIsImlhdCI6MTY2NzcyNDA2NH0.ROEqwTaVxAl6FIm3Zo8JL1lrQ01Uyx5v3GLHl0wNO52n64CJ8k_oeZOwFig0___pwDtUidVmHTxt0oMlE50NM8I4ZEEKrr7CtDs8cs13SXeSvHDa2ydLFjcWQewwsw8pf5F3FHEw-T2pcRBu4_1U0QmCpRNNiHbS1AWMgIMxlbycQgbiqbqfUV9YDwnL4eJIlowus_Nz0u3W9YdtuYkoMwezqFbQ_WrOvAQLwavdtwzBky_src_OD_7yJFHrYKxEwaf-vEuRSCUo0NeRNGBahp1L7AW5U5vJKldQXxkZ54nwQ5nkRsGYLfSHEWvJkBd6eMO3PpegcRqShMT0pJhIfta27LJrwK1Yhcp0XIBkWjel6cs1ew8X5f4vkyrVjnEefCYN4-uzuwLcal-mJ0c8EVW27cSKBQuLD-pH-HiVTYVj8fvoZ_ZTRxzIXhsR7pJ0rpcFdVjRiNim_fpSiOmW0vDYrM59sSgHfkPQ-S7p3a9eqVvGzeDpZFqLx51W39i-"
    old_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NjcxMTkyNjUsImlzcyI6InJlZnJlc2hfaXNzdWUiLCJpYXQiOjE2Njc3MjQwNjV9.tnCn-lqOUUCYNxP9PPzDKBcBvatw_M9_JBcXHKbA8oKwj7ri7O9XL_WZpUZU51tGmSGuW2hRwue2gu_QmSw5MwcAJUZm7Ii0bqZUBxUJbKHIOew1j1jQoYJ2dkEzIiqwqU-i5eLqJyiB1Go4mHiidhmD9L_OF6Mw_GCvEZpI1OGX5zMY7DxtBFIbM_rqJ-a_RecK7k7Izv7ZH_VNVVyHa4pVbF4QJpfiLlV7qvCKJBwpYRo9peQsbHQQkRxHAJrRXcIFxlzkii4EVCofbNauq0ifwBch1I8cK84WPnsJWoOjPl6zuZ7r7n55evyjjWwAVVSC2CVvbEBwNgysGlDKc7C5-VCW79jxZltxgfC3aTS5BHDqW0kSWb47AlngY7_rG3opGE6ieMkhDtO57K9YRCljGujV4nLfu55MzPZIQdTLZ-Rak7YzQLxzo3K_r2PuEPAx12KS0rm6Le0NzIp1ZlWrd8Gj8ZkX5dzN2i4yV4sju_bF74ALGiySMAtrCrMK"


    # invalid tokens
    # different issuer
    invalid_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjM3NjY4MDgzMDA5LCJpc3MiOiJhc2RhZGFzZGEiLCJpYXQiOjE2NjgwODY2MDl9.ToaSGQ1wHVCFYj0pOy1waCLOzx8fQr-sN9YzcinwAj7FuS0O5Vgqc89rIwLZwqnDdONBhM0iN2eZmacOkknMQSDo_QdfhswYPkTelbqKgpdhFP14kBbEnHpHjV-29mVe5ipyM3nuaVGsBgK75oReuoqlu2AGyrIlNWwmqS59d7PuaGyphLouZIOkd2wNFp2BTKJOr6F7znAr29m0jIixMBQi4OtPtmdxr624IPpSJcUojFfzzVcMpymD8hG60qfb--P-2olMbE8sF6fxUhQ524XdG9Ij0e6j36V_mkwThVWpfuJv66LzE_5tSwqoZPkgIcDG-HKPxiIv7v8ZjXMWmni4-bhp9PoMuqqlexvKhufc0AgXs80X-iwz4GqAaCwKwCkiphnPXx3vOMddDi0ZN4qDYrLr5D2DJnDbXMGZGciWw_ocO04dzaFkGcPIKlrmEeQ9NhlZpTvGtDXW1UK7gTaY7SLza_H2Jmz4Da0DMdUZoTW6jgdPELk45E0Uk-Z5"
    invalid_access_token2="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NjgwNjYxMzEsImlzcyI6ImFjY2Vzc19pc3N1ZSIsImlhdCI6MTY2ODA2MjUzMX0.rQvzVYoCvyAi9Xsn_j0Ia3YuXUJSHQOx_UYi1aQUqxk"
    # different secret key
    invalid_refresh_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3ZTEyMjEzMTIiLCJuYW1lIjoiSm9obiBhZGFkc2FkYSIsImlhdCI6MTUxNjIzOTAyMn0.sfju26ci_2NJ1t7pEjOmbqgE8WaDf7_ConljZIcyno4"



    # refresh_access_token(access_token, refresh_token)  # should be valid. return the same tokens
    refresh_access_token(access_token, old_access_token)  # log out
    # refresh_access_token(access_token, invalid_refresh_token)  # invalid token -> reject


    # refresh_access_token(old_access_token, refresh_token)
    # refresh_access_token(invalid_access_token, refresh_token)

 

if __name__ == '__main__':
    # authentication_test()
    # refresh_tokens_test()
    test()
    # authentication_test()

    