import os

from common import consts
from controllers.core import AppController
from controllers.utils import load_json
from models.db import get_db_hook
from models.models import BASE
from views.login import LoginForm
from common.consts import OUTPUT_DIR

class CoreDispatcher:
    def __init__(self,  args, app=None):
        self._args = args
        self._app = app
        connection, factory = get_db_hook(
            config=load_json(args.config),
            create=True,
            base=BASE,
        )
        AppController.set_connection(connection, factory)
        pass

    def start(self):


        form = LoginForm()  # build the entire form or GUI before showing it to the USR

        if not os.path.exists(os.path.join(consts.OUTPUT_DIR, 'remember_me.jl')):
            form.show()

        # form.show()