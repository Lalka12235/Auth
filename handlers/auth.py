from fastapi import APIRouter, Depends, status,HTTPException
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from data.pydantic_model_user import *
import bcrypt
import secrets
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError


router = APIRouter()

#settings for jwt token
SECRET_KEY = secrets.token_hex(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#temp test
users_db = {
    
}


#make hash_pass
def make_hash_pass(password: str):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password = hashed_password.decode('utf-8')
    return hashed_password

#verify pass == hash_pass
def verify_pass(password: str,hash_pass: str):
    return bcrypt.checkpw(password.encode('utf-8'), hash_pass.encode('utf-8'))

#auth user if in db
def authenticate_user(db,username: str,password: str):
    user = get_user(db,username)
    if not user:
        return False
    if not verify_pass(password,user.hash_pass):
        return False
    return user



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
    return None
    
async def get_current_user(token: Annotated[str,Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get('sub')
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(users_db,username=username)
    if user is None:
        raise credentials_exception
    return user

@router.post('/auth/register')
async def register_account(user: UserRegister):
    find_user = get_user(users_db, user.username)
    
    if find_user:
        return {'message': 'User already exists'}

    hashed_password = make_hash_pass(user.password)
    new_user = UserDb(username=user.username,hash_pass=hashed_password)
    users_db[user.username] = new_user.dict()
    
    return UserOut(username=user.username)


@router.post('/token/login')
async def login_for_acces_token(form_data: Annotated[OAuth2PasswordRequestForm,Depends()]) -> Token:
    user = authenticate_user(users_db,form_data.username,form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    acces_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_acces_token(
        data ={'sub': user.username},expires_delta=acces_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.get('/users/')
async def read_users(user: Annotated[str,Depends(get_current_user)]):
    return users_db
