from pydantic import BaseModel


class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(UserRegister):
    pass


class UserOut(BaseModel):
    username: str
    

class UserDb(UserRegister):
    username: str
    hash_pass: str

class Token(BaseModel):
    access_token: str
    token_type: str