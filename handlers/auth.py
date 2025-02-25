from fastapi import APIRouter, Depends, status,HTTPException
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from data.pydantic_model_user import *
import bcrypt
#try bcrypt 

router = APIRouter()

#temp test. add later db
users_db = {
    
}

def make_hash_pass(password: str):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password = hashed_password.decode('utf-8')
    return hashed_password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


@router.post('/auth/register{username}')
async def register_account(username: str,user: UserRegister) -> UserDb:
    if user.username not in users_db:
        user_hash_pass = make_hash_pass(user.password)
        users_db.update({'username': user.username, 'hash_pass' : user_hash_pass})
        return users_db[user.username]