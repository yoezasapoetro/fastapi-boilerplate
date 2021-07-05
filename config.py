from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings

app_config = Config('.env')

ORIGINS = app_config.get('ORIGINS', cast=CommaSeparatedStrings)
APP_VERSION = app_config.get('APP_VERSION', cast=str)
DEBUG = app_config.get('DEBUG', cast=bool, default=True)
DB_URL = app_config.get('DB_URL', cast=str)
ACCESS_TOKEN_EXPIRE_MINUTES = app_config.get('ACCESS_TOKEN_EXPIRE_MINUTES', cast=int)
SECRET_KEY = app_config.get('SECRET_KEY', cast=str)
ALGORITHM = app_config.get('ALGORITHM', cast=str)
