
class AppController:
    connection = None
    factory = None

    @classmethod
    def set_connection(cls, connection=None, factory=None):
        cls.connection = connection
        cls.factory = factory
        pass