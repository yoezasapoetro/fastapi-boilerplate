import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from pydantic import BaseModel
from tortoise.models import Model
from tortoise import fields

from config import *

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
auth_route = APIRouter()


class User(Model):
    id = fields.IntField(pk=True, source_field='idUser')
    name = fields.CharField(source_field='nama', max_length=150)
    username = fields.CharField(source_field='usernameApp', max_length=32)
    password = fields.CharField(source_field='passwordApp', max_length=32)
    group = fields.IntField(source_field='idGroup')
    active = fields.BooleanField(default=True, source_field='isAktif')

    class Meta:
        table = 'app_user'


# pydantic
class Credential(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# utils
def password_hash(password: str):
    hashed = hashlib.md5(password.encode())
    return hashed.hexdigest()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = expires_delta
    else:
        expire = timedelta(minutes=15)
    to_encode.update({"exp": datetime.utcnow() + expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def validate_user(credential: Credential):
    return await User.filter(username=credential.username,
                             password=password_hash(credential.password),
                             active=True).get_or_none()


async def get_user(username: str):
    return await User.filter(username=username, active=True)\
        .prefetch_related('faculty')\
        .values('id', 'username', 'fullName')


credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"}
)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(username=username)
    if user is None:
        raise credentials_exception

    return user[0]


@auth_route.post('/login', tags=['auth'])
async def auth_login(credential: OAuth2PasswordRequestForm = Depends()):
    user = await validate_user(Credential(username=credential.username, password=credential.password))

    if user is not None:
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return Token(
            access_token=access_token, token_type="bearer"
        )
    else:
        raise credentials_exception


@auth_route.get('/me', tags=['auth'])
async def auth_me(current_user: User = Depends(get_current_user)):
    return current_user


@auth_route.post('/logout', tags=['auth'])
async def auth_me(current_user: User = Depends(get_current_user)):
    return {
        'ok': True
    }
