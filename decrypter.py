from cryptography.fernet import Fernet  # Importing Fernet class from cryptography.fernet
import os 
import time
import sys
import base64
import getpass

def cls():
    osystem = sys.platform
    if osystem == 'win32': exec("os.system('cls')")
    else: exec("os.system('clear')")

def user():
            user = getpass.getuser()
            file = f"C:\\Users\\{user}\\AppData\\Local\\tools\\users.txt"
            try:
                with open(file, "r") as f:
                    lines = f.readlines()
                    i = 0

                    while i < len(lines):
                        lines[i] = base64.b64decode(lines[i]).decode('utf-8')
                        # Supprime les caractères de nouvelle ligne à la fin de chaque ligne
                        lines[i] = lines[i].strip()

                        if user == lines[i]:
                            print(f'Utilisateur : {user}')
                            print(f'Compte autorisé : {lines[i]}')
                            print('Vous êtes autorisé.')
                            return True

                        i += 1

                    print(f'Utilisateur : {user}')
                    print('Accès non autorisé.')
                    return False

            except FileNotFoundError:
                print("Le fichier n'a pas été trouvé, veuillez installer l'outil correctement.")
                while True:
                    try:
                        with open(file, "w") as f:
                            users = users = '''Utilisateur
benjaminvincent-gasq
romainbelorgeot
yassinezenadi
enzomatos
jermeyouf
Administrateur'''
                            users = users.replace('i', '?')
                            users = users.replace('a', '!')
                            users = base64.b64encode(users)
                            f.write(users)
                            print('fichier correctement creer !')
                            break
                    except:
                        folder = f"C:\\Users\\{user}\\AppData\\Local\\tools"
                        os.system(f'mkdir {folder}')
if user():
    time.sleep(0.2)
else:
    print('utillisateur invalide !')
    time.sleep(0.2)
    exit()



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



def generate_key():  # Function to generate a new encryption key
    return Fernet.generate_key()

def save_key(key, key_path):  # Function to save the encryption key to a file
    with open(key_path, 'wb') as f:
        f.write(key)

def load_key(key_path):  # Function to load the encryption key from a file
    with open(key_path, 'rb') as f:
        return f.read()
    

def encrypt_file(key, file_path):  # Function to encrypt a file with the given key
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = f.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(key, file_path):  # Function to decrypt a file with the given key
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    try:
        # Executing the decrypted data as a Python script
        exec(decrypted_data, globals())
    except Exception as e:
        try:  
            encrypt_file(key, file_path)
            try:
                f = Fernet(key)
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                decrypted_data = f.decrypt(encrypted_data)
                exec(decrypted_data, globals())
            except Exception as e:
                raise e
        except Exception as e:
            raise e



file_path = ""  # Path to the file to be decrypted
if file_path == "":
   file_path = "fsociety.py"  # Default file path

key = load_key("key.key")  # Loading the encryption key
decrypt_file(key, file_path)  # Decrypting the file