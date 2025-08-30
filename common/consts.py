import os

APP_NAME = "Inventory Management System"

APP_VERSION = (0, 0, 0)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
ASSETS_DIR = os.path.join(BASE_DIR, 'static')
OUTPUT_DIR = os.path.join(BASE_DIR, 'run')
ENV_DIR = os.path.join(BASE_DIR, 'env')

REMEMBER_ME_FILE_PATH = os.path.join(ENV_DIR, 'user.pkl')