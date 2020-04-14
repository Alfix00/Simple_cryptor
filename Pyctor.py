import base64, os, re
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Build():

    object_to_crypt = None
    fernet_key = None
    salted_key = None
    generated_key = None
    cypted_object = None
    decrypted_object = None
    formatted_decrypted = None

    def __init__(self, obj2crypt):
        self.object_to_crypt = obj2crypt

    def show_settings(self):
        print ("object_to_crypt = ", self.object_to_crypt)
        print ("fernet_key = ", self.fernet_key)
        print ("salted_key = ", self.salted_key)
        print ("generated_key = ", self.generated_key)
        print ("cypted_object = ", self.cypted_object)
        print ("decrypted_object = ", self.decrypted_object,"\n")

    def initialize_key(self):
        key = Fernet.generate_key()
        file = open('key','wb')
        file.write(key)
        file.close()
        self.fernet_key = key

    def read_key(self):
        file = open('key','rb')
        key = file.read()
        file.close()

    def setting_up(self):
        access_password = str(self.fernet_key)
        password = access_password.encode()
        salting = os.urandom(16)
        self.salted_key = salting
        kdf = PBKDF2HMAC(algorithm = hashes.SHA512(),
                        length = 64,
                        salt = salting,
                        iterations = 10000,
                        backend = default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.generated_key = key

    def encrypt_file(self):
        object_ = str(self.object_to_crypt)
        encoded = object_.encode()
        f = Fernet(self.fernet_key)
        encrypted = f.encrypt(encoded)
        self.cypted_object = encrypted

    def decrypt_file(self):
        f = Fernet(self.fernet_key)
        decrypted = f.decrypt(self.cypted_object)
        self.decrypted_object = decrypted


def __init__():
    setup = Build("test_string")
    setup.show_settings()
    setup.initialize_key()
    setup.read_key()
    setup.setting_up()
    setup.encrypt_file()
    setup.decrypt_file()
    setup.show_settings()

__init__()