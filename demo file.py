import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
import os

def encrypt_file():
    input_file_path = filedialog.askopenfilename()
    output_file_path = filedialog.asksaveasfilename()
    key = get_key_from_usb(usb_path.get())
    fernet = Fernet(key)

    with open(input_file_path, 'rb') as input_file, open(output_file_path, 'wb') as output_file:
        while True:
            chunk = input_file.read(64 * 1024)
            if not chunk:
                break
            encrypted_chunk = fernet.encrypt(chunk)
            output_file.write(encrypted_chunk)

    result_text.config(state="normal")
    result_text.delete("1.0", "end")
    result_text.insert("1.0", "File encrypted successfully!")
    result_text.config(state="disabled")

def decrypt_file():
    input_file_path = filedialog.askopenfilename()
    output_file_path = filedialog.asksaveasfilename()
    key = get_key_from_usb(usb_path.get())
    fernet = Fernet(key)

    with open(input_file_path, 'rb') as input_file, open(output_file_path, 'wb') as output_file:
        while True:
            chunk = input_file.read(64 * 1024)
            if not chunk:
                break
            decrypted_chunk = fernet.decrypt(chunk)
            output_file.write(decrypted_chunk)
