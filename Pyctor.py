import base64, os, re
from os import listdir
from os.path import isfile, join
from os import system, name 
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Build():

    name_of_file = None
    file_extension = None
    object_to_crypt = None
    fernet_key = None
    salted_key = None
    generated_key = None
    cypted_object = None
    decrypted_object = None
    formatted_decrypted = None

    def __init__(self, obj2crypt, filename):
        self.object_to_crypt = obj2crypt
        self.name_of_file = filename
        self.file_extension = str(filename.split(".", 3)[-1])

    def save_settings(self):
        isFile = os.path.isfile("./Saved_keys/"+self.name_of_file+"_KEYS")
        try:
            if isFile is False:
                os.mkdir("./Saved_keys/"+self.name_of_file+"_KEYS")
        except OSError:
            pass
        salted = open("./Saved_keys/"+self.name_of_file+"_KEYS/SALTED.KEY", "w")
        salted.write(str(self.salted_key))
        salted.close()
        generated = open("./Saved_keys/"+self.name_of_file+"_KEYS/GENERATED.KEY", "w")
        generated.write(str(self.generated_key))
        generated.close()

    def initialize_key(self):
        key = Fernet.generate_key()
        file = open("./Saved_keys/"+self.name_of_file+"_KEYS/FERNET.KEY",'wb')
        file.write(key)
        file.close()
        self.fernet_key = key

    def read_key(self):
        file = open("./Saved_keys/"+self.name_of_file+"_KEYS/FERNET.KEY",'rb')
        key = file.read()
        file.close()

    def setting_up(self):
        access_password = str(self.fernet_key)
        password = access_password.encode()
        salting = os.urandom(16)
        self.salted_key = salting
        kdf = PBKDF2HMAC(algorithm = hashes.SHA512(),
                        length = 32,
                        salt = salting,
                        iterations = 10000,
                        backend = default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.generated_key = key

    def encrypt_string(self):
        object_ = self.object_to_crypt
        f = Fernet(self.generated_key)
        encrypted = f.encrypt(object_)
        self.cypted_object = encrypted

    def decrypt_string(self):
        f = Fernet(self.generated_key)
        decrypted = f.decrypt(self.cypted_object)
        self.decrypted_object = decrypted

    def encrypt_file(self):
        with open("./Encrypted_folder/"+self.name_of_file+".encrypted", "wb") as file:
            file.write(self.cypted_object)
        print("ok")

    def decrypt_file(self):
        e = ".encrypted"
        with open("./Decrypted_folder/"+self.name_of_file, "wb") as file:
            file.write(self.decrypted_object)

    def get_keys(self):
        key_list = [str(self.fernet_key), str(self.salted_key), str(self.generated_key)]
        return key_list


def load_file(filename):
    with open("./Working_folder/"+filename , "rb") as file:
        file_data = file.read()
    return file_data


def option_one():
    setup = None
    onlyfiles = [f for f in listdir("./Working_folder") if isfile(join("./Working_folder", f))]
    print("Working folder file list:\n")
    for a, b in enumerate(onlyfiles, 1):
        print('{} {}'.format(a, b))
    file_name = input(str("Set index or filename: "))
    is_digit = representsInt(file_name)
    if is_digit:
        objective = onlyfiles[int(file_name,)-1]
        setup = Build(load_file(objective), str(objective))
    else:
        if file_name in onlyfiles:
            setup = Build(load_file(file_name), str(objective))
        else:
            print("[i] File not found or wrong name [i]")
    return setup


def option_two(file_target):
    if isinstance(file_target, Build):
        file_target.initialize_key()
        print("Read key...")
        file_target.read_key()
        print("Setting UP...")
        file_target.setting_up()
        print("Encryption...")
        file_target.encrypt_string()
        file_target.encrypt_file()
        print("Saving settings...")
        file_target.save_settings()
        print("Done!")
    if file_target is None:
        print("Target file not loaded! please retry")

def option_three(file_target):
    if isinstance(file_target, Build):
        print("Decrypting file...")
        file_target.decrypt_string()
        file_target.decrypt_file()
        print("Done")


def option_four(file_target):
    if isinstance(file_target, Build):
        key_list = file_target.get_keys()
        print("Fernet Key: "+key_list[0])
        print("Salted Key: "+key_list[1])
        print("Generated Key : "+key_list[2])


def representsInt(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


def checkFolder():
    if not os.path.isfile("./Working_folder"):
        try:
            os.mkdir("Working_folder")
            os.mkdir("Encrypted_folder")
            os.mkdir("Decrypted_folder")
            os.mkdir("Saved_Keys")
        except OSError:
            pass

def menu():
    exit = False
    file_target = None
    while exit is False:
        try:
            clear()
            print('GitHub: https://github.com/Alfix00')
            print('\n---------------| Pyctor  |------------\n')
            print('    1) Choose File')
            print('    2) Encrypt File.')
            print('    3) Decrypt File')
            print('    4) Show Keys \n ')
            print('    0) Exit.')
            print('----------------------------------[Dev by Alfix00]')
            choice = int(input("\n\tChoice: "))
            clear()
            if choice == 0:
                print("\n\n-> Exit from the program!\n")
                exit = True
            if choice < 1 or choice > 4 and choice != 0:
                if choice != 0:
                    print('Error! back to menu... ')
            if choice == 1:
                file_target = option_one()
            if choice == 2:
                option_two(file_target)
            if choice == 3:
                option_three(file_target)
            if choice == 4:
                option_four(file_target)
            if exit is False:
                input("\nPress Enter to continue...")
        except KeyboardInterrupt:
            print("\n\n-> Exit from the program!\n")
            exit = True

def clear(): 
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear') 

def __init__():
    checkFolder()
    menu()

__init__()
