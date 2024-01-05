import tkinter as tk
from tkinter import filedialog, simpledialog
from tkinter import ttk
from cryptography.fernet import Fernet
import os
import gzip
import shutil
from tqdm import tqdm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

# Callback function for when the default text in message_text is clicked
def on_message_click(event):
    if message_text.get("1.0", "end-1c") == "Enter a message or encrypted bytes...":
        message_text.delete("1.0", "end")
        message_text.config(fg='black')  # Change text color to black

# Callback function for when the default text in message_text is left
def on_message_leave(event):
    if not message_text.get("1.0", "end-1c"):
        message_text.insert("1.0", "Enter a message or encrypted bytes...")
        message_text.config(fg='grey')  # Change text color to grey

# Function to initiate file encryption
def encrypt_file():
    file_selection_window("Encrypt")

# Function to initiate file decryption
def decrypt_file():
    file_selection_window("Decrypt")

# Function to create a window for file selection
def file_selection_window(mode):
    file_selection_window = tk.Toplevel(root)
    file_selection_window.title(f"{mode} File")

    # Input frame for source file
    input_frame = ttk.Frame(file_selection_window, padding="10")
    input_frame.grid(row=0, column=0, padx=10, pady=10)

    input_label = ttk.Label(input_frame, text=f"Select {mode} Source File:")
    input_path_entry = ttk.Entry(input_frame, width=40, state="readonly")
    input_path_button = ttk.Button(input_frame, text="Browse", command=lambda: browse_file(input_path_entry))

    # Output frame for destination file
    output_frame = ttk.Frame(file_selection_window, padding="10")
    output_frame.grid(row=1, column=0, padx=10, pady=10)

    output_label = ttk.Label(output_frame, text=f"Select {mode} Destination File:")
    output_path_entry = ttk.Entry(output_frame, width=40, state="readonly")
    output_path_button = ttk.Button(output_frame, text="Browse", command=lambda: browse_save_location(output_path_entry))

    # Checkboxes for additional options
    compress_checkbox = ttk.Checkbutton(file_selection_window, text="Compress File", variable=compress_var)
    shred_checkbox = ttk.Checkbutton(file_selection_window, text="Shred Original File", variable=shred_var)

    # Button to perform file operation
    encrypt_file_button = ttk.Button(file_selection_window, text=f"{mode} File",
                                     command=lambda: perform_file_operation(mode, input_path_entry.get(), output_path_entry.get(),
                                                                              compress_var.get(), shred_var.get()))

    # Grid layout for widgets
    input_label.grid(row=0, column=0, pady=5, sticky="w")
    input_path_entry.grid(row=0, column=1, pady=5, padx=5, sticky="ew")
    input_path_button.grid(row=0, column=2, pady=5, padx=5, sticky="e")

    output_label.grid(row=0, column=0, pady=5, sticky="w")
    output_path_entry.grid(row=0, column=1, pady=5, padx=5, sticky="ew")
    output_path_button.grid(row=0, column=2, pady=5, padx=5, sticky="e")

    compress_checkbox.grid(row=2, column=0, pady=10, sticky="w")
    shred_checkbox.grid(row=3, column=0, pady=5, sticky="w")

    encrypt_file_button.grid(row=4, column=0, pady=10, padx=10, sticky="ew")

# Callback function to browse and select a file
def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.config(state="normal")
    entry.delete(0, "end")
    entry.insert(0, file_path)
    entry.config(state="readonly")

# Callback function to browse and select a save location
def browse_save_location(entry):
    save_path = filedialog.asksaveasfilename()
    entry.config(state="normal")
    entry.delete(0, "end")
    entry.insert(0, save_path)
    entry.config(state="readonly")

# Function to perform file encryption or decryption
def perform_file_operation(mode, input_path, output_path, compress, shred):
    try:
        # Get the encryption key from USB and password
        key = get_key_from_usb(usb_path.get(), get_password())
        fernet = Fernet(key)

        # Add .gz extension if compressing
        if compress:
            output_path += ".gz"

        if mode == "Encrypt":
            # Initialize progress bar for encryption
            progress_bar = tqdm(total=os.path.getsize(input_path), unit='B', unit_scale=True, desc=f'{mode}ing')
            with open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                if compress:
                    with gzip.open(output_file, 'wb') as compressed_file:
                        process_chunks(input_file, compressed_file, fernet, mode, progress_bar)
                else:
                    process_chunks(input_file, output_file, fernet, mode, progress_bar)
            progress_bar.close()
            # Shred the original file if specified
            if shred:
                shred_file(input_path)
        else:
            if input_path.endswith(".gz"):
                output_path = output_path[:-3]  # remove .gz extension
                with gzip.open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                    process_chunks(input_file, output_file, fernet, mode)
            else:
                with open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
                    process_chunks(input_file, output_file, fernet, mode)
            # Shred the original file if specified
            if shred:
                shred_file(input_path)

        # Update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", f"File {mode.lower()}ion successful!")
        result_text.config(state="disabled")

    except Exception as e:
        # Handle exceptions and update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", f"File {mode.lower()}ion failed. {str(e)}")
        result_text.config(state="disabled")

# Function to process file chunks
def process_chunks(input_file, output_file, fernet, mode, progress_bar=None):
    while True:
        chunk = input_file.read(64 * 1024)
        if not chunk:
            break
        # Encrypt or decrypt the chunk
        if mode == "Encrypt":
            processed_chunk = fernet.encrypt(chunk)
        else:
            processed_chunk = fernet.decrypt(chunk)
        output_file.write(processed_chunk)
        # Update progress bar if available
        if progress_bar:
            progress_bar.update(len(processed_chunk))

# Function to securely shred a file by overwriting with zeros
def shred_file(file_path):
    with open(file_path, 'wb') as file:
        file.write(b'\x00' * os.path.getsize(file_path))

# Function to encrypt a message
def encrypt_message():
    try:
        # Get encryption key from USB and password
        key = get_key_from_usb(usb_path.get(), get_password())
        fernet = Fernet(key)
        # Encrypt the message
        message = message_text.get("1.0", "end-1c")
        encrypted_bytes = fernet.encrypt(message.encode()).decode()
        # Update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Encrypted Message:\n" + encrypted_bytes)
        result_text.config(state="disabled")
    except Exception as e:
        # Handle exceptions and update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Encryption failed. Check the USB drive or input.")
        result_text.config(state="disabled")

# Function to decrypt a message
def decrypt_message():
    try:
        # Get encryption key from USB and password
        key = get_key_from_usb(usb_path.get(), get_password())
        fernet = Fernet(key)
        # Decrypt the message
        user_input = message_text.get("1.0", "end-1c")
        encrypted_bytes = bytes(user_input, 'utf-8')
        decrypted_string = fernet.decrypt(encrypted_bytes).decode()
        # Update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Decrypted Message:\n" + decrypted_string)
        result_text.config(state="disabled")
    except Exception as e:
        # Handle exceptions and update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Decryption failed. Check that the USB drive is correct/has a key or verify input.")
        result_text.config(state="disabled")

# Function to generate a new encryption key and save it to the USB drive
def generate_key():
    try:
        # Get the path to the USB drive
        usb_drive_path = usb_path.get()

        # Check if the key file already exists
        key_file_path = os.path.join(usb_drive_path, "encrypted_key.key")
        if os.path.exists(key_file_path):
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.insert("1.0", "Key file already exists on the USB drive. Use the existing key.")
            result_text.config(state="disabled")
            return

        # Generate a new key
        new_key = Fernet.generate_key()

        # Get a password from the user
        password = simpledialog.askstring("Password", "Enter a password for key encryption:", show='*')
        if not password:
            return

        # Encrypt and save the new key to a file on the USB drive
        encrypt_key_with_password(usb_drive_path, new_key, password)

        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "New key generated and encrypted, then saved to the USB drive.")
        result_text.config(state="disabled")
    except Exception as e:
        # Handle exceptions and update result text
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", f"Error generating or saving the new key. {str(e)}")
        result_text.config(state="disabled")

# Function to retrieve the encryption key from the USB drive
def get_key_from_usb(usb_path, password):
    try:
        return decrypt_key_with_password(usb_path, password)
    except FileNotFoundError:
        raise FileNotFoundError("Encrypted key file not found on the USB drive.")
    except Exception as e:
        raise Exception(f"Error decrypting key: {str(e)}")

# Function to encrypt the encryption key with a password and save it to a file on the USB drive
def encrypt_key_with_password(usb_path, key, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations for better security
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key_derived = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    encrypted_key = Fernet(key_derived).encrypt(key)

    with open(os.path.join(usb_path, "encrypted_key.key"), "wb") as encrypted_key_file:
        encrypted_key_file.write(salt + encrypted_key)

# Function to decrypt the encryption key with a password
def decrypt_key_with_password(usb_path, password):
    with open(os.path.join(usb_path, "encrypted_key.key"), "rb") as encrypted_key_file:
        data = encrypted_key_file.read()
        salt = data[:16]
        encrypted_key = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Same number of iterations as during encryption
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key_derived = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    decrypted_key = Fernet(key_derived).decrypt(encrypted_key)
    return decrypted_key

# Function to get a password from the user
def get_password():
    password = simpledialog.askstring("Password", "Enter your password:", show='*')
    return password

# Create the main application window
root = tk.Tk()
root.title("Allcrypt Encryption/Decryption")

# Boolean variables for checkboxes
compress_var = tk.BooleanVar()
shred_var = tk.BooleanVar()

# Configure styles for widgets
style = ttk.Style()
style.configure("TButton", padding=(10, 5), font=('Helvetica', 10))
style.configure("TLabel", font=('Helvetica', 12))
style.configure("TCheckbutton", font=('Helvetica', 12))

# Widgets for USB path and message input
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

# Bind events for default text in message_text
message_text.insert("1.0", "Enter a message or encrypted bytes...")
message_text.bind("<FocusIn>", on_message_click)
message_text.bind("<FocusOut>", on_message_leave)

root.mainloop()
