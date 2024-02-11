import urllib.request
import os
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
file_ip = config.get('parametres', "ip_file")

class getip:
    def write_publicip(file_ip=file_ip):
        print('finding your public ip adress please wait.', end="\r")
        i=0
        while i<stop:
            try:
                publicip=urllib.request.urlopen('http://ip.42.pl/raw').read()
                print('finding your public ip adress please wait..\r')
                publicip = publicip.decode('utf-8')
                print('finding your public ip adress please wait...\r')
                print(f'public ip found : {publicip}')
                with open(file_ip, "w") as f:
                    f.write(str(publicip))
                    return publicip
                break
            except:
                print("error can't get ur public ip !\r")
                i+=1
    def get_publicip():
        try:
            with open(file_ip, "r") as f:
                publicip = f.read()
                return publicip
        except:
            print(f'error file : {file_ip} don\'t exist or is inacessible')