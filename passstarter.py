import time
import os
with open('numbers.txt', 'w') as f:
    f.write(input('nombre de mot de passe a générer : '))
i=0
stop = int(input('nombre de fentre a ouvrir : '))
while i<stop:
    os.startfile('passgen.py')
    i+=1
