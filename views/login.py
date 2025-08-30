import os
import re

from PyQt6.QtWidgets import QWidget, QGridLayout, QLabel, QMessageBox, QLineEdit, QPushButton, QCheckBox
from PyQt6.QtGui import QIcon, QAction
# from cryptography.fernet import Fernet
from sqlalchemy import func

from common.consts import APP_NAME, OUTPUT_DIR
from controllers.core import AppController
from utilities.utils import BinarySerializer, generate_random_password
from views.consts import UNHIDDEN_EYE_ICON_PATH, HIDDEN_EYE_ICON_PATH
from views.core import MainApp
from views.custom import QClickableLabel
from views.styles import GENERAL_QLabel_STYLESHEET, GENERAL_QLineEdit_STYLESHEET, GENERAL_QPushButton_STYLESHEET, \
    SMALLER_QLabel_STYLESHEET


# saved externally - 3rd party software / env
# serialization - JSON, Binary, Local DB - SQLite


# this code has the minimum memory usage and the highest performance
class ForgetPasswordForm(QWidget):
    """ This "window" is a QWidget. If it has no parent, it will appear as a free-floating window as we want.
    """

    def __init__(self, parent=None, ):
        super(ForgetPasswordForm, self).__init__()
        self.parent = parent
        self.__init_ui()

        layout = QGridLayout()

        label_name = QLabel('Email')
        label_name.setStyleSheet(GENERAL_QLabel_STYLESHEET)
        layout.addWidget(label_name, 0, 0)

        self.lineEdit_username = QLineEdit()
        self.lineEdit_username.setStyleSheet(GENERAL_QLineEdit_STYLESHEET)
        self.lineEdit_username.setPlaceholderText('Please enter your email...')
        layout.addWidget(self.lineEdit_username, 0, 1, )

        button_check = QPushButton('Check')
        button_check.adjustSize()
        button_check.setStyleSheet(GENERAL_QPushButton_STYLESHEET)

        button_check.clicked.connect(self.check_password)
        layout.addWidget(button_check, 1, 1, )

        button_back = QPushButton('Back')
        # button_back.adjustSize()
        button_back.setStyleSheet(GENERAL_QPushButton_STYLESHEET)
        button_back.clicked.connect(self.return_to_login_page)
        layout.addWidget(button_back, 1, 0, 1, 1)

        # layout.setRowMinimumHeight(10, 75)
        layout.setContentsMargins(10, 0, 10, 0)
        self.setLayout(layout)

    def __init_ui(self):
        self.setWindowTitle(APP_NAME + ' -- Forget Password Form')
        height = 150  # consts.FORGET_PASSWORD_SCREEN_HEIGHT
        width = 400  # consts.FORGET_PASSWORD_WIDTH
        self.resize(width, height)
        self.setMinimumHeight(height)
        self.setMaximumHeight(height)

        self.setMinimumWidth(width)
        self.setMaximumWidth(width)

        pass

    def check_password(self):
        msg = QMessageBox()
        email = self.lineEdit_username.text().lower()
        if email is None or email == '':
            msg.setText('Please enter an email to validate.')
            msg.exec()
            return

        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if not re.fullmatch(regex, email):
            msg.setText('Text must be in an email format.')
            msg.exec()
            return


        self.__update_user_password(email)


    def return_to_login_page(self):
        # LoginForm(state='reverse').show()
        self.parent.show()
        self.hide()
        self.destroy()
        self.close()

    def __update_user_password(self, email):
        from models.models import User
        user = AppController.factory.session.query(User).filter(
            User.email == email,
            User.removed_at is None,
        ).first()

        msg = QMessageBox()
        if user is None:
            if user is None:
                msg.setText(f'Unable to find the user with email {email} in the system.')
                msg.exec()
                return

        user.password = generate_random_password()
        AppController.factory.session.commit()

        # TODO: send email with new password


        pass


class LoginForm(QWidget):
    def __init__(self, state=None):
        super(LoginForm, self).__init__()
        self.__init_ui()
        self.screen = None
        self._serializer = BinarySerializer()

        layout = QGridLayout()

        label_name = QLabel('Email')
        label_name.setStyleSheet(GENERAL_QLabel_STYLESHEET)
        self.lineEdit_username = QLineEdit()
        self.lineEdit_username.setStyleSheet(GENERAL_QLineEdit_STYLESHEET)
        self.lineEdit_username.setPlaceholderText('Please enter your email...')
        layout.addWidget(label_name, 0, 0)
        layout.addWidget(self.lineEdit_username, 0, 1, 1, 3, )

        label_password = QLabel('Password')
        label_password.setStyleSheet(GENERAL_QLabel_STYLESHEET)
        self.lineEdit_password = QLineEdit()
        self.lineEdit_password.setStyleSheet(GENERAL_QLineEdit_STYLESHEET)
        self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.lineEdit_password.setPlaceholderText('Please enter your password...')

        self.__show_pass_action = QAction(QIcon(UNHIDDEN_EYE_ICON_PATH), 'Show password', self)
        self.__show_pass_action.setCheckable(True)
        self.__show_pass_action.toggled.connect(self.show_password)  # connect to the event observer and execution
        self.lineEdit_password.addAction(self.__show_pass_action, QLineEdit.ActionPosition.TrailingPosition)

        layout.addWidget(label_password, 1, 0)
        layout.addWidget(self.lineEdit_password, 1, 1, 1, 3, )

        self.remember_me = QCheckBox('Remember me')
        self.remember_me.setStyleSheet(SMALLER_QLabel_STYLESHEET)
        layout.addWidget(self.remember_me, 2, 0)

        # TODO: explain this
        label_forget_password = QClickableLabel('Forget Password?', self.forget_password, )
        label_forget_password.setStyleSheet(SMALLER_QLabel_STYLESHEET)
        layout.addWidget(label_forget_password, 2, 3)

        button_login = QPushButton('Login')
        button_login.setStyleSheet(GENERAL_QPushButton_STYLESHEET)
        button_login.clicked.connect(self.check_password)
        layout.addWidget(button_login, 3, 0, 1, 4, )

        layout.setRowMinimumHeight(2, 150)
        layout.setContentsMargins(15, 25, 15, 25)
        self.setLayout(layout)

        self._attempt_remember_me_login()

    def show_password(self, ):
        if self.lineEdit_password.echoMode() == QLineEdit.EchoMode.Normal:
            self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.__show_pass_action.setIcon(QIcon(UNHIDDEN_EYE_ICON_PATH))
        else:
            self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.__show_pass_action.setIcon(QIcon(HIDDEN_EYE_ICON_PATH))

    def __init_ui(self):
        self.setWindowTitle(APP_NAME + ' -- Login')
        height = 200  # consts.LOGIN_SCREEN_HEIGHT
        width = 400  # consts.LOGIN_SCREEN_WIDTH
        self.resize(width, height)
        self.setMinimumHeight(height)
        self.setMaximumHeight(height)

        self.setMinimumWidth(width)
        self.setMaximumWidth(width)

        pass

    def check_password(self):

        msg = QMessageBox()
        email = self.lineEdit_username.text().lower()
        password = self.lineEdit_password.text()
        if email is None or not email:
            msg.setText('Please enter an email.')
            msg.exec()
            return

        if password is None or not password:
            msg.setText('Please enter a password.')
            msg.exec()
            return

        # REGEX [regular expression]: do the basic text processing, check if the email format is valid
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if not re.fullmatch(regex, email):
            msg.setText('Email must be in an email format.')
            msg.exec()
            return

        user = self.__load_user_data(email, password)
        if user is None:
            msg.setText('User is not registered in the system.')
            msg.exec()
            return

        if self.remember_me.isChecked():
            self._serializer.write_jl(
                obj={
                    'email': email,
                    'password': password,
                },
                path=OUTPUT_DIR,
                name='remember_me',
            )

        self.next_screen(user)

    def forget_password(self, event):
        self.screen = ForgetPasswordForm(parent=self, )

        self.screen.show()
        self.hide()
        # self.destroy()
        # self.close()

    def next_screen(self, user):
        self.screen = MainApp(
            user=user,
        )
        self.screen.show()

        self.hide()
        self.destroy()
        self.close()
        pass

    def _attempt_remember_me_login(self):
        path = os.path.join(OUTPUT_DIR, 'remember_me.jl')
        if os.path.exists(path):
            data = self._serializer.read_jl(path=OUTPUT_DIR, name='remember_me')
        else:
            return None

        user = self.__load_user_data(
            email=data.get('email'), password=data.get('password')
        )
        self.next_screen(user)

    def __load_user_data(self, email, password):
        from models.models import User
        user = AppController.factory.session.query(User).filter(
            User.email == email,
            User.removed_at is None,
        ).first()

        if user is None:
            return None

        if user.password != password:
            return None

        return user

        # '''select * from users where email = {email} limit 1'''

