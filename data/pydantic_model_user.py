from pydantic import BaseModel

#rewrite this shit
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