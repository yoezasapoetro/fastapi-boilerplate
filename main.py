import logging

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.requests import Request
from fastapi.responses import ORJSONResponse
from fastapi.exceptions import RequestValidationError
from tortoise.contrib.fastapi import register_tortoise

from config import *
from auth import auth_route

__version__ = APP_VERSION

# debug tortoise
fmt = logging.Formatter(
    fmt="%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
sh = logging.FileHandler('slow_query.log')
sh.setLevel(logging.DEBUG)
sh.setFormatter(fmt)

# will print debug sql
logger_db_client = logging.getLogger("db_client")
logger_db_client.setLevel(logging.DEBUG)
logger_db_client.addHandler(sh)

app = FastAPI(
    debug=DEBUG,
    title='',
    description='',
    version=__version__,
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

app.include_router(
    prefix='/auth',
    router=auth_route,
    tags=['auth']
)

register_tortoise(app,
                  db_url=DB_URL,
                  modules={'models': ['auth']},
                  add_exception_handlers=True)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):

    return ORJSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": exc.errors(), "body": exc.body, "req": {
            'url': request.url, 'method': request.method
        }}),
    )
