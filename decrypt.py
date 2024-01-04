import tkinter as tk
from cryptography.fernet import Fernet

def decrypt_message():
    key = b'hfi6NBSUz1R9avqs_S9spwld0fY1tseZRQcFcuV_P8c='
    fernet = Fernet(key)
    user_input = message_text.get("1.0", "end-1c")  # Get the encrypted bytes from the Text widget
    try:
        encrypted_bytes = bytes(user_input, 'utf-8')
        decrypted_string = fernet.decrypt(encrypted_bytes).decode()
        result_text.config(state="normal")  # Enable text editing
        result_text.delete("1.0", "end")  # Clear previous result
        result_text.insert("1.0", "Decrypted String: " + decrypted_string)  # Display the result
        result_text.config(state="disabled")  # Disable text editing for result
    except Exception as e:
        result_text.config(state="normal")  # Enable text editing
        result_text.delete("1.0", "end")  # Clear previous result
        result_text.insert("1.0", "Decryption failed. Check the input or key.")  # Display the error message
        result_text.config(state="disabled")  # Disable text editing for result

# Create the main window with a larger size
window = tk.Tk()
window.title("Pramay Decryption")
window.geometry("500x400")  # Set the window size to 500x400

# Create and configure widgets
message_label = tk.Label(window, text="Enter the encrypted bytes:")
message_text = tk.Text(window, height=5, width=40)  # Make the Text widget bigger
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_message)
result_text = tk.Text(window, height=5, width=40, wrap=tk.WORD)  # Enable text wrapping
result_text.config(state="disabled")  # Disable text editing for result

# Pack widgets
message_label.pack()
message_text.pack()
decrypt_button.pack()
result_text.pack()

window.mainloop()
