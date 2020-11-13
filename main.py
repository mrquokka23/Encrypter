"""
Projekti autor: Armin Mere

Salanõunikul oli vaja saata ülisalajsat informatsiooni teisele osapoolele ilma, et keegi seda vahepeal kergesti lugeda ei saaks.
Seetõttu pöördus ta minu poole palvega kirjutada programm, mis jagab faili kaheks niimoodi, et ühte faili omades poleks seda kergesti võimalik lugeda.
Programm krüpteerib tekstifaili lausehaaval suvaliselt ära ning loob ka võtmefaili. Programmiga on võimalik nii faile krüpteerida kui ka dekrüpteerida.

Programm küsib kasutajalt:
---kas kasutaja soovib faili krüpteerida või dekrüpteerida
---krüpteeritava faili või dekrüpteeritava faili ja võtmefaili nime
---krüpteeritud faili, dekrüpteeritud faili ja võtmefaili nimed kuvatakse ekraanil

Kasutatavad failid peavad olema programmiga samas kaustas!
Programm töötab ainult tekstifailidega(.txt)!
"""

import re       #library regular expressionite kasutamiseks
import random   #Library suvaliste arvude saamiseks
import string   #Library tähtede numbrikoodide saamiseks
import os       #Library erinevate süsteemifunktsioonide kasutamiseks
import time     #Library aja viivituste lisamiseks
import colorama #Library terminali värvide kasutamiseks Windowsi operatsioonisüsteemis
from base64 import b64decode, b64encode     #Library base64 kodeerimiseks ja dekodeerimiseks
from termcolor import colored               #Library terminali värvide kasutamiseks
from Cryptodome.Cipher import Salsa20, AES  #Library erinevate krüptograafiafunktsioonide kasutamiseks

# Terminali värvide seadistamine
colorama.init()
os.system('color')

# Funktsioon parooli genereerimiseks
def get_passphrase(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

# Krüpteerimise ja dekrüpteerimise näited võetud Cryptodome Library dokumentatsioonist

# Funktsioon AES krüpteerimiseks
def AESEncrypt(in_string):
    encryptionkey1 = get_passphrase(16)
    encryptionkey = str.encode(encryptionkey1)
    cipher = AES.new(encryptionkey, AES.MODE_EAX)
    nonce = cipher.nonce
    msg, tag = cipher.encrypt_and_digest(in_string.encode('utf-8'))
    return [encryptionkey1, msg, tag, nonce]

# Funktsioon AES dekrüpteerimiseks
def AESDecrypt(in_string, key, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    msg = cipher.decrypt(in_string)
    try:
        cipher.verify(tag)
        return msg
    except ValueError:
        print(colored("Krüpteerimisvõti on vale või vigane!", 'red'))

# Funktsioon Salsa20 krüpteerimiseks
def Salsa20Encrypt(in_string):
    encryptionkey1 = get_passphrase(32)
    encryptionkey = str.encode(encryptionkey1)
    cipher = Salsa20.new(key=encryptionkey)
    msg = cipher.nonce + cipher.encrypt(in_string.encode('utf-8'))
    return [msg, encryptionkey1]

# Funktsioon Salsa20 dekrüpteerimiseks
def Salsa20Decrypt(in_string, key):
    msg_nonce = in_string[:8]
    ciphertext = in_string[8:]
    cipher = Salsa20.new(key=key, nonce=msg_nonce)
    msg = cipher.decrypt(ciphertext)
    return msg

# Funktsioon krüpteerimiseks
def encrypt(file_sentences, in_file, p, u):
    for i in range(len(file_sentences)): # tsükkel, mis käib lausete arv kordi
        # Suvalise krüpteeringu valimine
        a = random.randint(0, 1)
        encrypted = cyphers[a](file_sentences[i])

        # Krüpteeritud lausete ja krüpteerimismeetodi faili kirjutamine
        encrypted_file = open(f"{in_file}encrypted{p}.txt", 'a')
        if a == 0:
            encrypted_file.writelines('0' + "," + b64encode(encrypted[1]).decode('utf-8') + '\n')
        else:
            encrypted_file.writelines('1' + "," + b64encode(encrypted[0]).decode('utf-8') + '\n')
        encrypted_file.close()

        # Krüpteerimisvõtme ja AES puhul tag-i ja nonce-i faili kirjutamine
        # Kasutan base64 encode-i, et oleks turvalisem ja et pärast oleks failist kergem infot lugeda
        key_file = open(f"{in_file}key{u}.txt", 'a')
        if a == 0:  # AES krüpteeritud
            key_file.write(b64encode(encrypted[0].encode('utf-8')).decode('utf-8'))
            key_file.write(",")
            key_file.write(b64encode(encrypted[2]).decode('utf-8'))
            key_file.write(",")
            key_file.write(b64encode(encrypted[3]).decode('utf-8'))
            key_file.write('\n')
        else:       # Salsa20 krüpteeritud
            key_file.write(b64encode(encrypted[1].encode('utf-8')).decode('utf-8'))
            key_file.write('\n')
        key_file.close()

# Funktsioon krüpteeritud failidest informatsiooni kättesaamiseks
def readFiles(in_file, in_file1):
    if os.path.exists(in_file + ".txt") and os.path.exists(infile1 + ".txt"):   # Failide olemasolukontroll
        encrypted_file = open(in_file + ".txt", 'r')

        # Krüpteeritud faili ridade arvu leidmine ja selle kasutamine tühja multidimensionaalse jada valmistamiseks
        line_count_encrypted = 0
        for line in encrypted_file:
            line_count_encrypted += 1
        lines = [['0'] * 5 for k in range(line_count_encrypted)]
        encrypted_file.close()

        # Võtmefaili lidade arvu leidmine
        key_file = open(in_file1 + ".txt", 'r')
        line_count_key = 0
        for line in key_file:
            line_count_key += 1
        key_file.close()

        if line_count_encrypted == line_count_key:  # Krüpteeritud faili ja võtmefaili ridade arvu võrdsuse kontroll

            # Krüpteeritud faili ligemine ja sealt iga rea lõikumine komakohtadest, et lisada see 'lines' jadasse
            encrypted_file = open(in_file + ".txt", 'r')
            i = 0
            for line in encrypted_file:
                for a in range(len(line.split(','))):
                    if a == 0:
                        lines[i][a] = line.split(',')[a]
                    else:
                        if len(line) % 4 != 0:
                            line.join('=' * (len(line) % 4))

                        lines[i][a] = b64decode(line.split(',')[a])

                i += 1
            encrypted_file.close()

            # Võtmefaili ligemine ja sealt iga rea lõikumine komakohtadest, et lisada see 'lines' jadasse
            key_file = open(in_file1 + ".txt", 'r')
            i = 0
            for line in key_file:
                for a in range(len(line.split(','))):

                    try:
                        lines[i][a + 2] = b64decode(line.split(',')[a])
                    except:
                        pass
                i += 1

            return lines # Krüpteeritud sõnumit ja krüpteerimisvõtmeid sisaldava jada tagastamine

# Funktsioon dekrüpteerimiseks
def decrypt(in_file, in_file1, k):
    lines = readFiles(in_file, in_file1)    # Krüpteeritud info küsimine 'readFiles' funktsioonilt

    # Dekrüpteeritud info faili kirjutamine
    decrypted_file = open(f"decrypted{k}.txt", 'a')
    for line in lines:
        if line[0] == '0':
            msg = AESDecrypt(line[1], line[2], line[3], line[4])
        else:
            msg = Salsa20Decrypt(line[1], line[2])
        decrypted_file.write(msg.decode('utf-8'))
    decrypted_file.close()

'''▼▼▼▼---------------------------------------Peamine kood----------------------------------------------▼▼▼▼'''

# Krüpteeringufunktsioone sisaldav jada, mida kasutad suvalise krüpteeringu valimiseks
cyphers = [AESEncrypt, Salsa20Encrypt]

# Kontroll-lausete seadistamine
passed = False
file1exists = False
file2exists = False
os.system('cls')    # Terminali tühjendamine
while not passed:   # Inim-vigade kontroll
    os.system('cls')# Terminali tühjendamine vigade korral

    # Teksti terminali värviliselt kuvamine ja kasutajasisendi küsimine
    print(colored("Teretulemast ülisalajasse krüpteerijasse!", 'green'))
    print(colored("[0]", 'blue'), colored("krüpteeri", 'yellow'))
    print(colored("[1]", 'blue'), colored("dekrüpteeri", 'yellow'))
    action = input(colored("Palun vali üks: ", 'green'))

    if action == '0':   # Kui kasutaja valik on krüpteeri
        print(colored("Krüpteeritav fail peab olema programmiga samas kaustas!", 'yellow'))
        infile = input(colored("Palun sisesta faili nimi: ", 'green'))
        if os.path.exists(infile):  # Kasutaja sisestatud faili olemasolu kontroll
            file1exists = True
        if file1exists:  # Kui fail on olemas, siis on kasutaja läbinud inim-vigade kontrolli
            passed = True
        infile = re.sub(r"\.txt", '', infile) # Regexi abil faili laiendi eemaldamine muutujast

        #Unikaalse failinime valimine ja kontroll
        j = 0
        while os.path.exists(f"{infile}encrypted{j}.txt"):
            j += 1
        l = 0
        while os.path.exists(f"{infile}key{l}.txt"):
            l += 1

        # Sisendfaili regexi abil lauseteks lõikamine ja muutujasse lisamine
        file = open(infile + ".txt", encoding="UTF-8")
        text = file.read()
        sentences = re.findall(r"\w+[^.!?]*[.!?]", text)
        file.close()

        encrypt(sentences, infile, j, l)    # Lausete krüpteerimine

        # Krüpteeringu edukuse kontroll
        if os.path.exists(f"{infile}encrypted{j}.txt") and os.path.exists(f"{infile}key{j}.txt"):
            print(
                colored(f"Krüpteeritud faili nimi on \"{infile}encrypted{j}.txt\" ja \"{infile}key{l}.txt\"", 'green'))
        else:
            print(colored("Tekkis viga faili krüpteerimisel", 'red'))

    elif action == '1': # Kui kasutaja valik on dekrüpteeri
        print(colored("Dekrüpteeritavad failid peavad olema programmiga samas kaustas!", 'yellow'))
        infile = input(colored("Palun sisesta krüpteeritud faili nimi: ", 'green'))
        if os.path.exists(infile):  # Kasutaja sisestatud faili olemasolu kontroll
            file1exists = True
        infile1 = input(colored("Palun sisesta võtme faili nimi: ", 'green'))
        if os.path.exists(infile1): # Kasutaja sisestatud faili olemasolu kontroll
            file2exists = True
        if file1exists and file2exists:
            passed = True
        infile = re.sub(r"\.txt", '', infile)   # Regexi abil faili laiendi eemaldamine muutujast
        infile1 = re.sub(r"\.txt", '', infile1) # Regexi abil faili laiendi eemaldamine muutujast

        # Unikaalse failinime valimine ja kontroll
        j = 0
        while os.path.exists(f"decrypted{j}.txt"):
            j += 1

        decrypt(infile, infile1, j)     # Failide dekrüpteerimine

        # Krüpteeringu edukuse kontroll
        if os.path.exists(f"decrypted{j}.txt"):
            print(colored(f"Dekrüpteeritud faili nimi on \"decrypted{j}.txt\"", 'green'))
        else:
            print(colored("Tekkis viga faili dekrüpteerimisel", 'red'))

    else:   # Kui kasutaja ei valinud ei 1 ega 0, siis läheb algusesse tagasi
        print(colored("Palun vali kas 1 või 0!", 'red', attrs=['underline']))
        time.sleep(7)       # Oota 7 sekundit
        os.system('cls')    # Terminali tühjendamine
    if not passed and (action == 0 or action == 1): # Vigade püüdmine
        print(colored(
            "Dekrüpteeritavad failid peavad olema programmiga samas kaustas! Palun kontrollige, kas failid eksisteerivad!",
            'red', attrs=['underline']))
