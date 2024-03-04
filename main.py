import tkinter as tk
from tkinter import filedialog, simpledialog
from tkinter import ttk
import cryptography
from cryptography.fernet import Fernet
import os
import gzip
import shutil
from tqdm import tqdm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

def main():

    def on_message_click(event):
        if message_text.get("1.0", "end-1c") == "Enter a message or encrypted bytes...":
            message_text.delete("1.0", "end")
            message_text.config(fg='black')


    def on_message_leave(event):
        if not message_text.get("1.0", "end-1c"):
            message_text.insert("1.0", "Enter a message or encrypted bytes...")
            message_text.config(fg='grey')


    def encrypt_file():
        file_selection_window("Encrypt")


    def decrypt_file():
        file_selection_window("Decrypt")


    def file_selection_window(mode):
        file_selection_window = tk.Toplevel(root)
        file_selection_window.title(f"{mode} File")


        input_frame = ttk.Frame(file_selection_window, padding="10")
        input_frame.grid(row=0, column=0, padx=10, pady=10)

        input_label = ttk.Label(input_frame, text=f"Select {mode} Source File:")
        input_path_entry = ttk.Entry(input_frame, width=40, state="readonly")
        input_path_button = ttk.Button(input_frame, text="Browse", command=lambda: browse_file(input_path_entry))

        output_frame = ttk.Frame(file_selection_window, padding="10")
        output_frame.grid(row=1, column=0, padx=10, pady=10)

        output_label = ttk.Label(output_frame, text=f"Select {mode} Destination File:")
        output_path_entry = ttk.Entry(output_frame, width=40, state="readonly")
        output_path_button = ttk.Button(output_frame, text="Browse", command=lambda: browse_save_location(output_path_entry))

        compress_checkbox = ttk.Checkbutton(file_selection_window, text="Compress File", variable=compress_var)
        shred_checkbox = ttk.Checkbutton(file_selection_window, text="Shred Original File", variable=shred_var)

        encrypt_file_button = ttk.Button(file_selection_window, text=f"{mode} File",
                                        command=lambda: perform_file_operation(mode, input_path_entry.get(), output_path_entry.get(),
                                                                                compress_var.get(), shred_var.get()))

        input_label.grid(row=0, column=0, pady=5, sticky="w")
        input_path_entry.grid(row=0, column=1, pady=5, padx=5, sticky="ew")
        input_path_button.grid(row=0, column=2, pady=5, padx=5, sticky="e")

        output_label.grid(row=0, column=0, pady=5, sticky="w")
        output_path_entry.grid(row=0, column=1, pady=5, padx=5, sticky="ew")
        output_path_button.grid(row=0, column=2, pady=5, padx=5, sticky="e")

        compress_checkbox.grid(row=2, column=0, pady=10, sticky="w")
        shred_checkbox.grid(row=3, column=0, pady=5, sticky="w")

        encrypt_file_button.grid(row=4, column=0, pady=10, padx=10, sticky="ew")

    def browse_file(entry):
        file_path = filedialog.askopenfilename()
        entry.config(state="normal")
        entry.delete(0, "end")
        entry.insert(0, file_path)
        entry.config(state="readonly")

    def browse_save_location(entry):
        save_path = filedialog.asksaveasfilename()
        entry.config(state="normal")
        entry.delete(0, "end")
        entry.insert(0, save_path)
        entry.config(state="readonly")


    def perform_file_operation(mode, input_path, output_path, compress, shred):
        try:
            key = get_key_from_usb(usb_path.get(), get_password())
            fernet = Fernet(key)

            with open(input_path, 'rb') as input_file:
                input_data = input_file.read()

            if compress:
                output_path += ".gz"

            if mode == "Encrypt":
                print('Encrypting...')
                encrypted_data = fernet.encrypt(input_data)

                with open(output_path, 'wb') as output_file:
                    if compress:
                        with gzip.open(output_file, 'wb') as compressed_file:
                            compressed_file.write(encrypted_data)
                            print('Compressed')
                    else:
                        output_file.write(encrypted_data)
                if shred:
                    shred_file(input_path)
            elif mode == "Decrypt":
                print('Decrypting...')
                
                if input_path.endswith(".gz"):
                    output_path = output_path[:-3]  

                decrypted_data = fernet.decrypt(input_data)

                with open(output_path, 'wb') as output_file:
                    output_file.write(decrypted_data)
                        
                if shred:
                    shred_file(input_path)

            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", f"File {mode.lower()}ion successful!")
            result_text.config(state="disabled")

        except cryptography.fernet.InvalidToken:
            print('Invalid token. Check that the key or password is correct.')
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", f"Invalid token. Check that the key or password is correct.")
            result_text.config(state="disabled")
        except Exception as e:
            print('Exception occurred:', str(e))
            import traceback
            traceback.print_exc()
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", f"File {mode.lower()}ion failed. {str(e)}")
            result_text.config(state="disabled")


    def shred_file(file_path):
        with open(file_path, 'wb') as file:
            file.write(b'\x00' * os.path.getsize(file_path))

    def encrypt_message():
        try:
            key = get_key_from_usb(usb_path.get(), get_password())
            fernet = Fernet(key)
            message = message_text.get("1.0", "end-1c")
            encrypted_bytes = fernet.encrypt(message.encode()).decode()
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Encrypted Message:\n" + encrypted_bytes)
            result_text.config(state="disabled")
        except Exception as e:
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Encryption failed. Check the USB drive or input.")
            result_text.config(state="disabled")

    def decrypt_message():
        try:
            key = get_key_from_usb(usb_path.get(), get_password())
            fernet = Fernet(key)
            user_input = message_text.get("1.0", "end-1c")
            encrypted_bytes = bytes(user_input, 'utf-8')
            decrypted_string = fernet.decrypt(encrypted_bytes).decode()
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Decrypted Message:\n" + decrypted_string)
            result_text.config(state="disabled")
        except Exception as e:
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Decryption failed. Check that the USB drive is correct/has a key or verify input.")
            result_text.config(state="disabled")

    def generate_key():
        try:
            usb_drive_path = usb_path.get()

            key_file_path = os.path.join(usb_drive_path, "encrypted_key.key")
            if os.path.exists(key_file_path):
                result_text.config(state="normal")
                result_text.delete("1.0", "end")
                result_text.insert("1.0", "Key file already exists on the USB drive. Use the existing key.")
                result_text.config(state="disabled")
                return

            new_key = Fernet.generate_key()

            password = simpledialog.askstring("Password", "Enter a password for key encryption:", show='*')
            if not password:
                return

            encrypt_key_with_password(usb_drive_path, new_key, password)

            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "New key generated and encrypted, then saved to the USB drive.")
            result_text.config(state="disabled")
        except Exception as e:
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", f"Error generating or saving the new key. {str(e)}")
            result_text.config(state="disabled")

    def get_key_from_usb(usb_path, password):
        try:
            return decrypt_key_with_password(usb_path, password)
        except FileNotFoundError:
            raise FileNotFoundError("Encrypted key file not found on the USB drive.")
        except Exception as e:
            raise Exception(f"Error decrypting key: {str(e)}")

    def encrypt_key_with_password(usb_path, key, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=32,
            backend=default_backend()
        )
        key_derived = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        encrypted_key = Fernet(key_derived).encrypt(key)

        with open(os.path.join(usb_path, "encrypted_key.key"), "wb") as encrypted_key_file:
            encrypted_key_file.write(salt + encrypted_key)

    def decrypt_key_with_password(usb_path, password):
        with open(os.path.join(usb_path, "encrypted_key.key"), "rb") as encrypted_key_file:
            data = encrypted_key_file.read()
            salt = data[:16]
            encrypted_key = data[16:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000, 
            salt=salt,
            length=32,
            backend=default_backend()

        )
        key_derived = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        decrypted_key = Fernet(key_derived).decrypt(encrypted_key)
        return decrypted_key

    def get_password():
        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        return password

    root = tk.Tk()
    root.title("Allcrypt Encryption/Decryption")

    compress_var = tk.BooleanVar()
    shred_var = tk.BooleanVar()

    style = ttk.Style()
    style.configure("TButton", padding=(10, 5), font=('Helvetica', 10))
    style.configure("TLabel", font=('Helvetica', 12))
    style.configure("TCheckbutton", font=('Helvetica', 12))

    usb_label = ttk.Label(root, text="Enter the path to the USB drive:")
    usb_path = ttk.Entry(root, width=40)
    message_label = ttk.Label(root, text="Enter a message or encrypted bytes:")
    message_text = tk.Text(root, height=5, width=40, font=('Helvetica', 12), fg='grey')
    encrypt_message_button = ttk.Button(root, text="Encrypt Message", command=encrypt_message)
    decrypt_message_button = ttk.Button(root, text="Decrypt Message", command=decrypt_message)
    encrypt_file_button = ttk.Button(root, text="Encrypt File", command=encrypt_file)
    decrypt_file_button = ttk.Button(root, text="Decrypt File", command=decrypt_file)
    generate_key_button = ttk.Button(root, text="Generate New Key for this USB", command=generate_key)
    result_text = tk.Text(root, height=5, width=40, wrap=tk.WORD, font=('Helvetica', 12))
    result_text.config(state="disabled")

    compress_checkbox = ttk.Checkbutton(root, text="Compress Files", variable=compress_var)
    shred_checkbox = ttk.Checkbutton(root, text="Shred Original File", variable=shred_var)

    usb_label.grid(row=0, column=0, columnspan=2, pady=10, padx=10, sticky="w")
    usb_path.grid(row=1, column=0, columnspan=2, pady=5, padx=10, sticky="ew")
    message_label.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="w")
    message_text.grid(row=3, column=0, columnspan=2, pady=5, padx=10, sticky="ew")
    encrypt_message_button.grid(row=4, column=0, pady=10, padx=10, sticky="ew")
    decrypt_message_button.grid(row=4, column=1, pady=10, padx=10, sticky="ew")
    encrypt_file_button.grid(row=5, column=0, pady=10, padx=10, sticky="ew")
    decrypt_file_button.grid(row=5, column=1, pady=10, padx=10, sticky="ew")
    generate_key_button.grid(row=6, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
    result_text.grid(row=7, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    compress_checkbox.grid(row=8, column=0, columnspan=2, pady=10, padx=10, sticky="w")
    shred_checkbox.grid(row=9, column=0, columnspan=
    2, pady=10, padx=10, sticky="w")

    message_text.insert("1.0", "Enter a message or encrypted bytes...")
    message_text.bind("<FocusIn>", on_message_click)
    message_text.bind("<FocusOut>", on_message_leave)

    root.mainloop()

if __name__ == '__main__':
    main()
