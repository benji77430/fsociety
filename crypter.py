from cryptography.fernet import Fernet
import os
import sys
import time
import queue
def cls():
    osystem = sys.platform
    if osystem == 'win32': exec("os.system('cls')")
    else: exec("os.system('clear')")
drives = []
for drive in range(65, 91):
    if os.path.exists(f"{chr(drive)}:\\"):
        drives.append(f"{chr(drive)}:/code_encoded.txt")
i=0
check = 0
while check != 1:
    for drive in drives:
            try:
                with open(drive, 'r') as f:
                    code = f.read()
                    exec(code)
                    code_pin = code()
                    print(code_pin)
                    print(drive)
                    check = 1
                    break
            except FileNotFoundError:
                if i >= 1:
                    print('Veuillez insérer le token')
                    i+=1

if code_pin != 1000000000000007:

    exit()

else:

    print('code correct')

    time.sleep(0.4)
    cls()

def generate_key():
    return Fernet.generate_key()

def save_key(key, key_path):
    with open(key_path, 'wb') as f:
        f.write(key)
        print('key succesfully wrote')


def load_key(key_path):
    with open(key_path, 'rb') as f:
        return f.read()

def encrypt_file(key, file_path):
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = f.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(key, file_path):
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data

choice = ""

key_path = "key.key"
try:
    key = load_key(key_path)
    print('key is : ', key)
except: 
    pass

try:
    path = sys.argv[2]
except:
    path = "fsociety.py"

try:
    file_path = path
except:
    file_path = "fsociety.py"

try: choice = sys.argv[1]
except: 
    try:
        encrypt_file(key, file_path)
    except:
        print('error ')


try:
    if file_path == "":
        file_path = "fsociety.py"
    if choice == "-get-key":
        print("Key : ", key)
    if choice == "-decrypt":
        decrypted_data = decrypt_file(key, file_path) 
        with open(file_path, 'wb') as file: 
            file.write(decrypted_data)
    if choice == "-crypt":
        try:
            encrypt_file(key, file_path)
        except:
            print('error ')
    if choice == "--keygen":
        print('it will overwrite the current key if there is one !')
        sure = input('type Y to confirme')
        if sure in ("Y", "y", "yes", "YES", "o", "O", "oui", "OUI"):
            new_key = generate_key()
            save_key(new_key, key_path)
    if choice in ("-help", "-h", "--h", "-HELP", "-H", "-?", "", None):
        print('python decrypter.py [action to do] [file path]')
        print('action :')
        print('     -get-key')
        print('     -decrypt')
        print('     -crypt')
        print('     --keygen')
        print('     -help')
        print('file path configuration:')
        print('     default is C:\\fsociety\\fsociety.py')
        print('     exemple : C:/your/file/path.txt')
        print('     exemple : file.txt')
        time.sleep(5)
except Exception as e:
    print('make sure ton complte argument like that python decrypter.py <action> <file_path>')
    print('you can use -help to see all parameters')
    print(f'error : {e}')
        