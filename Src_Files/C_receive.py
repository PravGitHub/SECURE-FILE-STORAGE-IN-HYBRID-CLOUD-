from cryptography.fernet import Fernet
import os
import pyrebase
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random

#-------------Firebase config information - Please specify before execution-------------
config_private = {
    "apiKey": "",
    "authDomain": "",
    "databaseURL": "",
    "projectId": "",
    "storageBucket": "",
    "messagingSenderId": ""
  }

config_public = {
    "apiKey": "",
    "databaseURL": "",
    "projectId": "",
    "storageBucket": "",
    "messagingSenderId": ""
  }


private = pyrebase.initialize_app(config_private)
public = pyrebase.initialize_app(config_public)

db_private = private.database()
store_public = public.storage()

count = 0

#-----------Decrypting files using fernet-----------
def d_fern(el, p):
    global store_public, count
    name = el.val()['file'+str(p)]
    store_public.child("files/"+ name).download("E:\\"+name)
    temp_key = el.val()['key'+str(p)]
    key = str.encode(temp_key.strip("b'"))
    fer = Fernet(key)

    temp = []
    with open("E:\\"+name,"rb") as fil:
        encrypted = fil.readlines()

        for token in encrypted:
            s= fer.decrypt(token)
            temp.append(str(s).strip("b'").replace('\n',''))
            count +=1
    os.remove("E:\\"+name)
    return temp

#-----------Decrypting files using RC4------------------------
def d_arc4(el, p):
    global store_public, count
    name = el.val()['file'+str(p)]
    store_public.child("files/"+ name).download("E:\\"+name)
    file_key = el.val()['key_file'+str(p)]
    store_public.child("files/"+ file_key).download("E:\\"+file_key)
    key=b''
    with open("E:\\" + file_key, "rb") as fi:
        key = fi.read()

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()

    temp = []
    with open("E:\\"+name,"rb") as fil:
        encrypted = fil.readlines()

        for token in encrypted:
            s= decryptor.update(token.strip(b'\n'))
            temp.append(str(s).strip("b'"))
            count +=1

    os.remove("E:\\"+name)
    os.remove("E:\\" + file_key)
    return temp

#---------Fetching Meta data---------------------------
data=db_private.child("Key_Store/input3").get()
decrypted = []
#------------------------------------------------------
for el in data.each():
    par = el.val()['partitions']
    ptr = [0 for x in range(par)]

    for i in range(par):
        if el.val()['algo'+str(i)] == 0:
            decrypted.append(d_fern(el, i))
        elif el.val()['algo'+str(i)] == 1:
            decrypted.append(d_arc4(el,i))

    with open("E:\decrypted", "w") as fil: #Generating the decrypted file
        for i in range(count):
            j=i%par
            fil.write(decrypted[j][ptr[j]].replace("\\n","")+"\n")
            ptr[j]+=1

