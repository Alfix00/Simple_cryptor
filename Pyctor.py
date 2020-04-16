import base64, os, re
from os import listdir
from os.path import isfile, join
from os import system, name 
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#Start Build Class:

class Build():

    name_of_file = None
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

    def save_settings(self):
        isFile = os.path.isfile("./Saved_Keys/"+self.name_of_file+"_KEYS")
        try:
            if isFile is False:
                os.mkdir("./Saved_Keys/"+self.name_of_file+"_KEYS")
        except OSError:
            pass
        salted = open("./Saved_Keys/"+self.name_of_file+"_KEYS/SALTED.KEY", "w")
        salted.write(str(self.salted_key))
        salted.close()
        generated = open("./Saved_Keys/"+self.name_of_file+"_KEYS/GENERATED.KEY", "w")
        generated.write(str(self.generated_key))
        generated.close()

    def initialize_key(self):
        path = "./Saved_Keys/"+self.name_of_file+"_KEYS"
        isFile = os.path.isfile(path)
        try:
            if isFile is False:
                os.mkdir(path)
        except OSError:
            pass
        key = Fernet.generate_key()
        file = open('./Saved_Keys/'+self.name_of_file+'_KEYS/FERNET.KEY','wb')
        file.write(key)
        file.close()
        self.fernet_key = key


    def read_key(self):
        path = './Saved_Keys/'+self.name_of_file+'_KEYS/FERNET.KEY'
        isFile = os.path.isfile(path)
        try:
            if isFile is False:
                os.mkdir(path)
        except OSError:
            pass
        file = open(path,'rb')
        key = file.read()
        file.close()

    def setting_up(self):
        access_password = str(self.fernet_key)
        password = access_password.encode()
        salting = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm = hashes.SHA512(),
                        length = 32,
                        salt = salting,
                        iterations = 10000,
                        backend = default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.salted_key = salting
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
        path = "./Encrypted_folder/"+self.name_of_file+".encrypted"
        with open(path, "wb") as file:
            file.write(self.cypted_object)

    def decrypt_file(self):
        path = "./Decrypted_folder/"+self.name_of_file
        with open(path, "wb") as file:
            file.write(self.decrypted_object)

    def get_keys(self):
        key_list = [str(self.fernet_key), str(self.salted_key), str(self.generated_key)]
        return key_list

#<-- End of Build Class
#--> Options : 

def option_one(path, another=False):
    setup = None
    onlyfiles = [f for f in listdir(path) if isfile(join(path, f))]
    print("Working folder file list:\n")
    for a, b in enumerate(onlyfiles, 1):
        print('{} {}'.format(a, b))
    file_name = input(str("\nSet index or filename: "))
    is_digit = representsInt(file_name)
    if is_digit:
        objective = onlyfiles[int(file_name,)-1]
        if another is False:
            setup = Build(load_file(objective,path), str(objective))
        else:
            setup = load_file(objective,path)
    else:
        if file_name in onlyfiles:
            if another is False:
                setup = Build(load_file(file_name,path), str(objective))
            else:
                setup = load_file(objective,path)
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
    answer = False
    while answer is False:
        print("Do you want decrypt this file or another file? (Select file with '.encrypted' extension)\n")
        question = int(input("[0] Back to menu - [1] This file - [2] Another file : "))
        if question == 0:
            answer = True
        if question == 1:
            answer = True
            if isinstance(file_target, Build):
                print("Decrypting file...")
                file_target.decrypt_string()
                file_target.decrypt_file()
                print("Done")
        if question == 2:
            print("\n[i] Put and choose the file from Working_Folder directory\n ")
            target_file = option_one("./Working_folder", True)
            print("\n[i] Set the KEY to unlock the file: ")
            key = option_one("./Unlock_Keys",True)
            try: 
                access_p = str(key)
                access_p = re.search(r'\'(.*?)\'',access_p).group(1)
                key = access_p.encode()
                f = Fernet(key)
                path = "./Decrypted_folder/Unlocked_Files"
                decrypted = f.decrypt(target_file)
                with open(path+"/Decrypted", "wb") as file:
                    file.write(decrypted)
                print("\n -> Decrypted Succesfully!  Check in folder [./Decrypted_folder/Unlocked_Files] ")
                answer = True
            except:
                clear()
                print("Failed to decrypt file! - Wrong Key")
        elif question != 0:
            print("\n -> Invalid key! please use numbers [1,2,...] <- \n")


def option_four(file_target):
    if isinstance(file_target, Build):
        key_list = file_target.get_keys()
        print("Fernet Key: "+key_list[0])
        print("Salted Key: "+key_list[1])
        print("Generated Key : "+key_list[2])

# <-- End Options 
# --> Usefull Methods 

def load_file(filename,path):
    with open(path+"/"+filename , "rb") as file:
        file_data = file.read()
    return file_data


def checkFolder():
    path = "./Decrypted_folder/Unlocked_Files"
    w = "Working_folder"
    e = "Encrypted_folder"
    d = "Decrypted_folder"
    s = "Saved_Keys"
    k = "Unlock_Keys"
    dot = "./"
    try:
        if not os.path.isfile(dot+k):
            os.mkdir(k)
        if not os.path.isfile(dot+w):
            os.mkdir(w)
        if not os.path.isfile(dot+e):
            os.mkdir(e)
        if not os.path.isfile(dot+d):
            os.mkdir(d)
        if not os.path.isfile(dot+s):
            os.mkdir(s)
        if not os.path.isfile(path):
                os.mkdir(path)
    except OSError:
        pass


def representsInt(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


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
                file_target = option_one("./Working_folder")
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
