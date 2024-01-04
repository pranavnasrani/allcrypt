import tkinter as tk
from cryptography.fernet import Fernet


# Your secret key (keep this safe)

key = b'hfi6NBSUz1R9avqs_S9spwld0fY1tseZRQcFcuV_P8c='

# Create a Fernet object using the key
fernet = Fernet(key)

def encrypt_message():
    message = message_text.get("1.0", "end-1c")
    encrypted_bytes = fernet.encrypt(message.encode()).decode()
    result_text.config(state="normal")
    result_text.delete("1.0", "end")
    result_text.insert("1.0", "Encrypted Bytes: " + encrypted_bytes)
    result_text.config(state="disabled")

def decrypt_message():
    user_input = message_text.get("1.0", "end-1c")
    try:
        encrypted_bytes = bytes(user_input, 'utf-8')
        decrypted_string = fernet.decrypt(encrypted_bytes).decode()
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Decrypted String: " + decrypted_string)
        result_text.config(state="disabled")
    except Exception as e:
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", "Decryption failed. Check the input or key.")
        result_text.config(state="disabled")

root = tk.Tk()
root.title("Allcrypt Encryption/Decryption")

message_label = tk.Label(root, text="Enter a message or encrypted bytes:")
message_text = tk.Text(root, height=5, width=40)
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_message)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_message)
result_text = tk.Text(root, height=5, width=40, wrap=tk.WORD)
result_text.config(state="disabled")

message_label.pack()
message_text.pack()
encrypt_button.pack()
decrypt_button.pack()
result_text.pack()

root.mainloop()
