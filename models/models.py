from sqlalchemy import Column, String, DateTime, Boolean, ARRAY, Index, Integer, Enum, \
    JSON, Interval, BigInteger, Float
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.sql import func
from datetime import datetime
from sqlalchemy.orm import validates

from models import utils
from models.consts import UserType

# from models_package import BASE


try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base

BASE = declarative_base(cls=utils.Model)
print(BASE)

SCHEMA = 'inventory_management_s'  # Define schema name for all tables

USERTYPE_ENUM = Enum(UserType, name='UserType', schema=SCHEMA, create_type=True)


class User(BASE):
    """
    Represents the input data for data quality checks.
    Stores metadata about the data source, processing options, and validation settings.
    """

    __tablename__ = 'users'
    __table_args__ = (
        Index(f'idx_{__tablename__}_email', 'email', ),
        Index(f'idx_{__tablename__}_password', 'password', ),
        Index(f'idx_{__tablename__}_composite01', 'created_at', 'updated_at', 'removed_at', ),
        {'extend_existing': True, 'schema': SCHEMA},
    )

    email = Column(String(75), primary_key=True)  # Discriminator column to differentiate subclasses
    password = Column(String, nullable=False, )
    user_type = Column(USERTYPE_ENUM, nullable=False, default=UserType.REGULAR, server_default=UserType.REGULAR.value)

    # is_verified = Column(Boolean, nullable=False, default=True, )
    # password = Column(MutableList.as_mutable(ARRAY(String)), nullable=False, default=[])

    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=func.now(), nullable=False)
    removed_at = Column(DateTime, nullable=True, default=None)  # soft delete -- facebook

    # @validates()
    # def convert_to_upper(self, key, value):
    #     """Ensure the field is always uppercase."""
    #     return value.upper()

    @validates('email')
    def convert_to_lower(self, key, value):
        """Ensure the field is always uppercase."""
        return value.lower()

    # @validates('owner', )
    # def convert_to_title(self, key, value):
    #     """Ensure the field is always uppercase."""
    #     return value.title()

    def __str__(self):
        return f"{self.email}"

    def __eq__(self, other):
        if isinstance(other, str):
            return self.email == other

        elif isinstance(other, User):
            return self.email == other.email

        else:
            return False
            # raise TypeError(f"Cannot compare User with {type(other)}")



    def to_dict(self):
        return {
            'email': self.email,
            'password': self.password,
        }
