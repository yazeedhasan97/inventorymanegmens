import os
import pickle
import joblib



def generate_random_password(length: int = 10):
    import string
    import random
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class BinarySerializer:

    def write(self, obj: dict, path: str, name: str):
        os.makedirs(path, exist_ok=True)
        path = os.path.join(path, f'{name}.pickle')
        with open(path, 'wb') as f:
            pickle.dump(obj, f)

    def read(self, path: str, name: str):
        path = os.path.join(path, f'{name}.pickle')
        with open(path, 'rb') as f:
            return pickle.load(f)

    def write_jl(self, obj: dict, path: str, name: str):
        os.makedirs(path, exist_ok=True)
        path = os.path.join(path, f'{name}.jl')
        with open(path, 'wb') as f:
            joblib.dump(obj, f)

    def read_jl(self, path: str, name: str):
        path = os.path.join(path, f'{name}.jl')
        with open(path, 'rb') as f:
            return joblib.load(f)