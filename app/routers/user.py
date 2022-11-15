from fastapi import APIRouter, Depends

from layer import refresh_access_token, issue_new_access_token, create_new_tokens
from dependencies import validate_access_token, validate_refresh_token


router = APIRouter(
    prefix="/api/user",
    tags=["user"]
)


@router.get('/')
def root():

    print('user root')
    return {}
