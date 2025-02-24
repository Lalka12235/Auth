from fastapi import APIRouter
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from data.pydantic_model_user import *


router = APIRouter()

#temp test. add later db
users_db = {
    
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


@router.get('/auth/{username}')
async def get_account(user: UserOut):
    if user.username in users_db:
        return {'Found': True,user.username: user}
    return {'Found': False}

@router.post('/auth/{username}')
async def create_account(user: UserRegister):
    if user:
        users_db.update({user.username: user})
        return {'Create account': True}
    return {'Create account': False}