import hashlib
import sqlite3
import uuid
import pyperclip
import os
import base64
from tkinter import *
from tkinter import simpledialog
from functools import partial
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# INITIALIZATION OF THE DATABASE
with sqlite3.connect('passwords.db') as db:
    cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS MASTERPASS (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    PASSWORD TEXT NOT NULL,
    RECOVERY TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS VAULT (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    WEBSITE TEXT NOT NULL,
    USERNAME TEXT NOT NULL,
    PASSWORD TEXT NOT NULL
)
""")


# CREATE POPUOP WINDOW
def popup_window(text):
    answer = simpledialog.askstring("Password Vault", text)
    return answer


# INITIALIZATION OF WINDOW
window = Tk()
window.title("Password Vault")


def hashPassword(input):
    hashedpass = hashlib.sha256(input.encode('utf-8')).hexdigest()
    return hashedpass


def first_Screen():
    window.geometry("250x150")
    for widget in window.winfo_children():
        widget.destroy()

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    def save_password(event=None):
        if txt.get() == txt1.get():
            sql = "DELETE FROM MASTERPASS WHERE ID = 1"
            cursor.execute(sql)

            hashedpass = hashPassword(txt.get())
            Key = hashPassword(str(uuid.uuid4().hex))
            recoveryKey = hashPassword(Key)

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO MASTERPASS (PASSWORD, RECOVERY) VALUES (?,?)"""
            cursor.execute(insert_password, [hashedpass, recoveryKey])
            db.commit()

            recoveryScreen(recoveryKey)
        else:
            txt1.delete(0, END)
            lbl.config(text="Password do not match")

    window.bind('<Return>', save_password)
    bt = Button(window, text="SAVE", command=save_password)
    bt.pack(pady=5)


def recoveryScreen(Key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry('400x120')
    lb1 = Label(window, text="Save this key to recover your password")
    lb1.config(anchor=CENTER)
    lb1.pack()

    lb2 = Label(window, text=Key)
    lb2.config(anchor=CENTER)
    lb2.pack()

    def copy_key(event=None):
        pyperclip.copy(lb2.cget("text"))

    bt = Button(window, text="COPY KEY", command=copy_key)
    bt.pack(pady=5)

    def done(event=None):
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=5)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry('250x125')
    lb1 = Label(window, text="Enter your recovery key")
    lb1.config(anchor=CENTER)
    lb1.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = txt.get()
        cursor.execute("SELECT RECOVERY FROM MASTERPASS WHERE ID = 1 AND RECOVERY = ?", [recoveryKeyCheck])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()
        if checked:
            first_Screen()
        else:
            txt.delete(0, END)
            lbl1.config(text="Invalid recovery key")

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x200")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def get_MasterPass():
        checkHashedPass = hashPassword(txt.get())
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM MASTERPASS WHERE ID = 1 AND PASSWORD = ?", [checkHashedPass])
        return cursor.fetchall()

    def checkpass(event=None):
        match = get_MasterPass()

        if match:
            passwordVault()
        else:
            txt.delete(0, END)
            lbl1.config(text="Incorrect Password")

    def resetPass():
        resetScreen()

    window.bind('<Return>', checkpass)
    button = Button(window, text="Submit", command=checkpass)
    button.pack(pady=10)

    button = Button(window, text="Reset Password", command=resetPass)
    button.pack(pady=10)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(popup_window(text1).encode(), encryptionKey)
        username = encrypt(popup_window(text2).encode(), encryptionKey)
        password = encrypt(popup_window(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO VAULT (WEBSITE, USERNAME, PASSWORD) VALUES (?,?,?)"""
        cursor.execute(insert_fields, [website, username, password])
        db.commit()

        passwordVault()

    def deleteEntry(inputed):
        cursor.execute("DELETE FROM VAULT WHERE ID = ?", (inputed,))
        db.commit()
        passwordVault()

    window.geometry("900x600")

    lbl = Label(window, text="Password Vault", font=("Arial Bold", 15))
    lbl.grid(row=0, column=1)

    button = Button(window, text="Add Password", command=addEntry)
    button.grid(column=1, pady=10, row=1)

    lbl = Label(window, text="Website", font=("Arial Bold", 13))
    lbl.grid(column=0, row=2, padx=80)

    lbl = Label(window, text="Username", font=("Arial Bold", 13))
    lbl.grid(column=1, row=2, padx=80)

    lbl = Label(window, text="Password", font=("Arial Bold", 13))
    lbl.grid(column=2, row=2, padx=80)

    cursor.execute("SELECT * FROM VAULT")
    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM VAULT")
            array = cursor.fetchall()

            if i == len(array):
                break

            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Arial", 12))
            lbl1.grid(column=0, row=i + 3, padx=80)

            lbl2 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Arial", 12))
            lbl2.grid(column=1, row=i + 3, padx=80)

            lbl3 = Label(window, text=(decrypt(array[i][3],encryptionKey)), font=("Arial", 12))
            lbl3.grid(column=2, row=i + 3, padx=80)

            button = Button(window, text="DELETE", command=partial(deleteEntry, array[i][0]))
            button.grid(column=3, row=i + 3, pady=10)

            i += 1

cursor.execute("SELECT * FROM MASTERPASS ")
if cursor.fetchall():
    loginScreen()
else:
    first_Screen()
window.mainloop()
