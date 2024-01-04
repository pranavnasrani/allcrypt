import tkinter as tk
from tkinter import filedialog
from tkinter import simpledialog
from cryptography.fernet import Fernet
import os
import gzip
import shutil
from tqdm import tqdm

def encrypt_file():
    file_selection_window("Encrypt")

def decrypt_file():
    file_selection_window("Decrypt")

def file_selection_window(mode):
    file_selection_window = tk.Toplevel(root)
    file_selection_window.title(f"{mode} File")

    input_label = tk.Label(file_selection_window, text=f"Select {mode} Source File:")
    input_path_entry = tk.Entry(file_selection_window, width=40, state="readonly")
    input_path_button = tk.Button(file_selection_window, text="Browse", command=lambda: browse_file(input_path_entry))

    output_label = tk.Label(file_selection_window, text=f"Select {mode} Destination File:")
    output_path_entry = tk.Entry(file_selection_window, width=40, state="readonly")
    output_path_button = tk.Button(file_selection_window, text="Browse", command=lambda: browse_save_location(output_path_entry))

    compress_checkbox = tk.Checkbutton(file_selection_window, text="Compress File", variable=compress_var)
    shred_checkbox = tk.Checkbutton(file_selection_window, text="Shred Original File", variable=shred_var)

    encrypt_file_button = tk.Button(file_selection_window, text=f"{mode} File",
                                     command=lambda: perform_file_operation(mode, input_path_entry.get(), output_path_entry.get(),
                                                                              compress_var.get(), shred_var.get()))

    input_label.grid(row=0, column=0, columnspan=2, pady=5)
    input_path_entry.grid(row=1, column=0, columnspan=2, pady=5)
    input_path_button.grid(row=1, column=2, pady=5, padx=5)

    output_label.grid(row=2, column=0, columnspan=2, pady=5)
    output_path_entry.grid(row=3, column=0, columnspan=2, pady=5)
    output_path_button.grid(row=3, column=2, pady=5, padx=5)

    compress_checkbox.grid(row=4, column=0, columnspan=2, pady=5)
    shred_checkbox.grid(row=5, column=0, columnspan=2, pady=5)

    encrypt_file_button.grid(row=6, column=0, columnspan=3, pady=10)

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
        key = get_key_from_usb(usb_path.get())
        fernet = Fernet(key)

        if compress:
            output_path += ".gz"

        if mode == "Encrypt":
            progress_bar = tqdm(total=os.path.getsize(input_path), unit='B', unit_scale=True, desc=f'{mode}ing')
            with open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                if compress:
                    with gzip.open(output_file, 'wb') as compressed_file:
                        process_chunks(input_file, compressed_file, fernet, mode, progress_bar)
                else:
                    process_chunks(input_file, output_file, fernet, mode, progress_bar)
            progress_bar.close()
            if shred:
                # Shred original file
                shred_file(input_path)
        else:
            # For decryption, check if the file is compressed
            if input_path.endswith(".gz"):
                output_path = output_path[:-3]  # remove .gz extension
                with gzip.open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                    process_chunks(input_file, output_file, fernet, mode)
            else:
                with open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                    process_chunks(input_file, output_file, fernet, mode)
            if shred:
                # Shred original file
                shred_file(input_path)

        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", f"File {mode.lower()}ion successful!")
        result_text.config(state="disabled")

    except Exception as e:
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", f"File {mode.lower()}ion failed. {str(e)}")
        result_text.config(state="disabled")

def process_chunks(input_file, output_file, fernet, mode, progress_bar=None):
    while True:
        chunk = input_file.read(64 * 1024)
        if not chunk:
            break
        if mode == "Encrypt":
            processed_chunk = fernet.encrypt(chunk)
        else:
            processed_chunk = fernet.decrypt(chunk)
        output_file.write(processed_chunk)
        if progress_bar:
            progress_bar.update(len(processed_chunk))

def shred_file(file_path):
    # Simple file shredder by overwriting with zeros
    with open(file_path, 'wb') as file:
        file.write(b'\x00' * os.path.getsize(file_path))

def encrypt_message():
    try:
        key = get_key_from_usb(usb_path.get())
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
        key = get_key_from_usb(usb_path.get())
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
        # Get the path to the USB drive
        usb_drive_path = usb_path.get()

        # Check if the key file already exists
        key_file_path = os.path.join(usb_drive_path, "secret_key.key")
        if os.path.exists(key_file_path):
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Key file already exists on the USB drive. Use the existing key.")
            result_text.config(state="disabled")
            return

        # Generate a new key
        new_key = Fernet.generate_key()

        # Save the new key to a file on the USB drive
        try:
            with open(key_file_path, "wb") as key_file:
                key_file.write(new_key)

            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "New key generated and saved to the USB drive.")
            result_text.config(state="disabled")
        except Exception as e:
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Error saving key. Check USB path and ensure there is no existing key.")
            result_text.config(state="disabled")
    except Exception as e:
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Error generating or saving the new key. Check the USB drive path.")
        result_text.config(state="disabled")

def get_key_from_usb(usb_path):
    key_file_path = os.path.join(usb_path, "secret_key.key")
    if os.path.exists(key_file_path):
        with open(key_file_path, "rb") as key_file:
            return key_file.read()
    else:
        raise FileNotFoundError("Key file not found on the USB drive.")

root = tk.Tk()
root.title("Allcrypt Encryption/Decryption")

compress_var = tk.BooleanVar()
shred_var = tk.BooleanVar()

usb_label = tk.Label(root, text="Enter the path to the USB drive:")
usb_path = tk.Entry(root, width=40)
message_label = tk.Label(root, text="Enter a message or encrypted bytes:")
message_text = tk.Text(root, height=5, width=40)
encrypt_message_button = tk.Button(root, text="Encrypt Message", command=encrypt_message)
decrypt_message_button = tk.Button(root, text="Decrypt Message", command=decrypt_message)
encrypt_file_button = tk.Button(root, text="Encrypt File", command=encrypt_file)
decrypt_file_button = tk.Button(root, text="Decrypt File", command=decrypt_file)
generate_key_button = tk.Button(root, text="Generate New Key for this USB", command=generate_key)
result_text = tk.Text(root, height=5, width=40, wrap=tk.WORD)
result_text.config(state="disabled")

compress_checkbox = tk.Checkbutton(root, text="Compress Files", variable=compress_var)
shred_checkbox = tk.Checkbutton(root, text="Shred Original File", variable=shred_var)

usb_label.grid(row=0, column=0, columnspan=2, pady=5)
usb_path.grid(row=1, column=0, columnspan=2, pady=5)
message_label.grid(row=2, column=0, columnspan=2, pady=5)
message_text.grid(row=3, column=0, columnspan=2, pady=5)
encrypt_message_button.grid(row=4, column=0, pady=5, padx=5)
decrypt_message_button.grid(row=4, column=1, pady=5, padx=5)
encrypt_file_button.grid(row=5, column=0, pady=5, padx=5)
decrypt_file_button.grid(row=5, column=1, pady=5, padx=5)
generate_key_button.grid(row=6, column=0, columnspan=2, pady=10)
result_text.grid(row=7, column=0, columnspan=2, pady=5)

compress_checkbox.grid(row=8, column=0, columnspan=2, pady=5)
shred_checkbox.grid(row=9, column=0, columnspan=2, pady=5)

root.mainloop()
