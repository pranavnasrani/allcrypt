import tkinter as tk
from cryptography.fernet import Fernet

def encrypt_message():
    key = b'hfi6NBSUz1R9avqs_S9spwld0fY1tseZRQcFcuV_P8c='
    fernet = Fernet(key)
    message = message_text.get("1.0", "end-1c")  # Get the message from the Text widget
    encrypted_bytes = fernet.encrypt(message.encode()).decode()
    result_text.config(state="normal")  # Enable text editing
    result_text.delete("1.0", "end")  # Clear previous result
    result_text.insert("1.0", "Encrypted Bytes: " + encrypted_bytes)  # Display the result
    result_text.config(state="disabled")  # Disable text editing

# Create the main window with a larger size
window = tk.Tk()
window.title("Pramay Decryption")
window.geometry("500x400")  # Set the window size to 500x400

# Create and configure widgets
message_label = tk.Label(window, text="Enter a message:")
message_text = tk.Text(window, height=5, width=40)  # Make the Text widget bigger
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_message)
result_text = tk.Text(window, height=5, width=40, wrap=tk.WORD)  # Enable text wrapping
result_text.config(state="disabled")  # Disable text editing for result

# Pack widgets
message_label.pack()
message_text.pack()
encrypt_button.pack()
result_text.pack()

window.mainloop()
