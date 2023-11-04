import binascii
import hashlib
import os
import secrets

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
    def create(cls, path: str, secret: Secret):
        if not os.path.exists(path):
            return cls.create_unchecked(path, secret)
        else:
            return None
        
    @classmethod
    def create_unchecked(cls, path: str, secret: Secret):
        key = cls(path)
        open(path, 'wb').write(secret.raw)
        open(key._sha256_path, 'w').write(secret.sha256_hex)
        return key

    def __init__(self, path: str):
        self._path = path

    @property
    def name(self):
        return os.path.basename(self._path)[:-4]

    @property
    def secret(self):
        data = open(self._path, 'rb').read()
        return Secret(data)
    
    @property
    def sha256_hex(self):
        try:
            return open(self._sha256_path, 'r').read()
        except FileNotFoundError:
            return None
        
    @property
    def is_valid(self):
        return self.secret.sha256_hex == self.sha256_hex
    
    @property
    def abs_path(self):
        return os.path.abspath(self._path)

    @property
    def _sha256_path(self):
        return self._path + ".sha256"

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

    def add_key(self, name: str, secret: Secret) -> FSKey:
        return FSKey.create(self._get_keyfile_path(name), secret)

    def set_key(self, name: str, secret: Secret) -> FSKey:
        return FSKey.create_unchecked(self._get_keyfile_path(name), secret)

    def backup(self, dest):
        for key in self.valid_keys:
            dest.set_key(key.name, key.secret)
        
    def _get_keyfile_path(self, name: str):
        return os.path.join(self._path, name + ".key")