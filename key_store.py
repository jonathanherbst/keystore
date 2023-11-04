import binascii
import hashlib
import json
import os
import secrets
import shutil
import time

class Secret:
    @classmethod
    def generate(cls, len=32):
        secret = secrets.token_bytes(len)
        return cls(secret)
    
    @classmethod
    def from_hex(cls, hex):
        secret = binascii.a2b_hex(hex)
        return cls(secret)

    def __init__(self, value: bytes):
        self._value = bytes(value)

    @property
    def raw(self):
        return self._value
    
    @property
    def hex(self):
        return binascii.b2a_hex(self.raw).decode()
    
    @property
    def sha256_hex(self):
        return hashlib.sha256(self.raw).hexdigest()
    
class FSKey:
    @classmethod
    def open_if_valid(cls, path: str):
        key = cls(path)
        if key.is_valid:
            return key
        else:
            return None
        
    @classmethod
    def create(cls, path: str, secret: Secret, extra_params: dict() = None):
        if not os.path.exists(path):
            return cls.create_unchecked(path, secret, extra_params)
        else:
            return None
        
    @classmethod
    def create_unchecked(cls, path: str, secret: Secret, extra_params: dict() = None):
        params = extra_params or {}
        params["sha256_hex"] = secret.sha256_hex
        params["creation_date"] = time.time()
        key = cls(path)
        open(path, 'wb').write(secret.raw)
        json.dump(params, open(key._params_path, 'w'))
        return key

    def __init__(self, path: str):
        self._path = path
        self._params = None

    @property
    def name(self):
        return os.path.basename(self._path)[:-4]
    
    @property
    def params(self) -> dict():
        if not self._params:
            try:
                self._params = json.load(open(self._params_path, 'r'))
            except:
                return {}
        return self._params
    
    def set_params(self, params: dict()):
        self._params = self.params.extend(params)
        json.dump(self._params, open(self._params_path, 'w'))

    @property
    def secret(self):
        try:
            data = open(self._path, 'rb').read()
            return Secret(data)
        except FileNotFoundError:
            return None
    
    @property
    def sha256_hex(self):
        return self.params.get("sha256_hex")
        
    @property
    def is_valid(self):
        secret = self.secret
        return secret and secret.sha256_hex == self.sha256_hex
    
    @property
    def path(self):
        return self._path
    
    @property
    def abs_path(self):
        return os.path.abspath(self._path)
    
    def copy(self, dest):
        shutil.copyfile(self._path, dest._path)
        shutil.copyfile(self._params_path, dest._params_path)

    @property
    def _params_path(self):
        return self._path + ".params"

class FSKeyStore:
    @classmethod
    def open(cls, path: str):
        if os.path.isdir(path):
            return cls(path)
        else:
            return None
    
    @classmethod
    def create_or_open(cls, path: str):
        os.makedirs(path, exist_ok=True)
        return cls(path)

    def __init__(self, path: str):
        self._path = path

    @property
    def all_keys(self):
        return [FSKey(path) for path in self._key_paths]
    
    @property
    def valid_keys(self):
        return [FSKey.open_if_valid(path) for path in self._key_paths]

    @property
    def _key_paths(self):
        return [os.path.join(self._path, path) for path in os.listdir(self._path) if path.endswith(".key")]

    def get_key(self, name: str) -> FSKey:
        return FSKey.open_if_valid(self._get_keyfile_path(name))

    def get_key_unchecked(self, name: str) -> FSKey:
        return FSKey(self._get_keyfile_path(name))

    def add_key(self, name: str, secret: Secret, extra_params: dict() = None) -> FSKey:
        return FSKey.create(self._get_keyfile_path(name), secret, extra_params)

    def set_key(self, name: str, secret: Secret, extra_params: dict() = None) -> FSKey:
        return FSKey.create_unchecked(self._get_keyfile_path(name), secret, extra_params)
        
    def _get_keyfile_path(self, name: str):
        return os.path.join(self._path, name + ".key")