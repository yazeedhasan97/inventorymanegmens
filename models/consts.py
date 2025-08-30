from enum import Enum

ALL = "ALL"

# For retry attempts on DB level
STOP_AFTER_ATTEMPT = 3
WAIT_EXPONENTIAL_MULTIPLIER = 1
WAIT_EXPONENTIAL_MIN = 2
WAIT_EXPONENTIAL_MAX = 10


class UserType(Enum):
    REGULAR = "REGULAR"
    ADMIN = "ADMIN"
    STAFF = "STAFF"


