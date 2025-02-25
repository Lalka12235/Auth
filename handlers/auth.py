from fastapi import APIRouter, Depends, status,HTTPException
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from data.pydantic_model_user import *
import bcrypt
from passlib.context import CryptContext
import secrets
from datetime import datetime, timedelta, timezone
import jwt


router = APIRouter()

#settings for jwt token
SECRET_KEY = secrets.token_hex(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#temp test. add later db
users_db = {
    
}


#make hash_pass
def make_hash_pass(password: str):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password = hashed_password.decode('utf-8')
    return hashed_password

#verify pass == hash_pass
def verify_pass(password: str,hash_pass: str):
    return pwd_context.verify(password,hash_pass)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

#create jwt token
def create_acces_token(data: dict,expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15) 
    to_encode.update({'exp': expire})
    encode_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encode_jwt

#get data from db
def get_user(db,username:str):
    if username in db:
        user_dict = db[username]
        return UserDb(**user_dict)
    


@router.post('/auth/register{username}')
async def register_account(username: str,user: UserRegister) -> UserDb:
    if user.username not in users_db:
        user_hash_pass = make_hash_pass(user.password)
        users_db.update({'username': {'username': user.username,'password': user.password}})
        return users_db[user.username]