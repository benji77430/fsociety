import requests
import shutil
import os
RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

def remove_empty_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.readlines()
    with open(file_path, 'w', encoding='utf-8') as f:
        for line in content:
            if line.strip():  # Si la ligne n'est pas vide
                f.write(line)
    print(f'fichier  {RED}{file_path}{RESET} modifié')
    
files = ['fsociety.py', 'keygen.py', 'miner.py', 'decrypter.py', 'context.py', 'config.cfg', 'version.txt', "updater.py"]
i=0
for file in files:
    response = requests.get(f"https://raw.githubusercontent.com/benji77430/fsociety/main/{file}")
    if response.status_code == 200:
        file_path = "C:\\fsociety\\" + file
        with open("C:\\fsociety\\"+file, "w", encoding="utf-8") as f:
            f.write(response.text)
            remove_empty_lines(file_path)
        if file =="fsociety.py":
            os.system('python crypter.py')  
        print(f"fichier numéro {RED}{i+1}/{len(files)}{RESET}\nle fichier : {RED}{file}{RESET} a été correctement mis a jour.")
        i+=1
    else:
        print("une erreur est survenu.")
   
print('')
input('press a key to start the tools')
os.system('python keygen.py')
