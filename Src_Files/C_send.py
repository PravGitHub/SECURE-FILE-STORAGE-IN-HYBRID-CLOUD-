from cryptography.fernet import Fernet
import os
import pyrebase
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random

n=3 #Number of partitions
i=0

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
    "authDomain": "",
    "databaseURL": "",
    "projectId": "",
    "storageBucket": "",
    "messagingSenderId": ""
  }
#----------------------------------------------------------------------

data = {"partitions": n}

private = pyrebase.initialize_app(config_private)
public = pyrebase.initialize_app(config_public)

db_private = private.database()
store_public = public.storage()

data_list = []
for ii in range(n):
    data_list.append(list())


#---------fetching data-------------
with open("E:\input.txt", "r") as text:
    global i,n

    for l in text.readlines():
        j = i % n
        data_list[j].append(l)
        i+=1
#---------------fernet encryption---------------
def e_fern(d_list,itr):
    name = str(Fernet.generate_key())
    data["file"+str(itr)] = name
    key = Fernet.generate_key()
    data["key"+str(itr)] = str(key)
    fern= Fernet(key)

    with open("E:\\"+name,'ab') as f:
        for y in range(len(d_list)):
            token = fern.encrypt(str.encode(d_list[y]))
            f.write(token)
            f.write(b'\n')

    store_public.child("files/" + name).put("E:\\" + name) # Push encrypted file part to public cloud

    os.remove("E:\\"+name)

#----------------RC4 encryption-----------------
def e_arc4(d_list,itr):
    data["algo"+str(itr)]= 1
    name = str(Fernet.generate_key())
    data["file"+str(itr)] = name
    key = os.urandom(16)
    kfile = str(Fernet.generate_key())
    data["key_file"+str(itr)] = kfile

    with open("E:\\"+kfile,'ab') as kf:
        kf.write(key)
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    with open("E:\\"+name,'ab') as f:
        for y in range(len(d_list)):
            token = encryptor.update(str.encode(d_list[y].strip()))
            f.write(token)
            f.write(b'\n')
    store_public.child("files/" + name).put("E:\\" + name) # Push encrypted file part to public cloud
    store_public.child("files/" + kfile).put("E:\\" + kfile) # Push key file to public cloud
    os.remove("E:\\"+name)
    os.remove("E:\\"+kfile)

#--------------Randomized algorithm selection-------
for itr in range(n):
    rand = random.randint(0,n-2)
    if rand == 0:
        data["algo" + str(itr)] = 0
        e_fern(data_list[itr],itr)
    elif rand == 1:
        data["algo" + str(itr)] = 1
        e_arc4(data_list[itr],itr)

#---------------Push data to Private cloud------------

if db_private.child("Key_Store/input3").get().val() is not None:
    db_private.child("Key_Store/input3").remove()
db_private.child("Key_Store/input3").push(data)