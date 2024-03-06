# Allcrypt Encryption/Decryption

Allcrypt is a Python application for file and message encryption/decryption using Fernet symmetric key cryptography for Windows and Linux users.

## Features

- Encrypt and decrypt files securely
- Encrypt and decrypt messages
- Generate and manage encryption keys on a USB drive

## Installation

1. Install the latest package using pip:

    ```bash
    pip install allcrypt
    ```

2. Run the Allcrypt GUI:

    ```bash
    allcrypt
    ```
3. You can also install from the installer in the releases. (recommended for inexperienced users or those without Python)
## Usage

### Encrypt a Message

1. Launch the Allcrypt GUI.
2. Enter the path to the USB drive in the provided field.
3. Enter the message or encrypted bytes in the text box.
4. Click the "Encrypt Message" button.
5. Follow any prompts to enter the password for key encryption.

### Decrypt a Message

1. Launch the Allcrypt GUI.
2. Enter the path to the USB drive in the provided field.
3. Enter the encrypted message in the text box.
4. Click the "Decrypt Message" button.
5. Follow any prompts to enter the password for key decryption.

### Encrypt a File

1. Launch the Allcrypt GUI.
2. Enter the path to the USB drive in the provided field.
3. Click the "Encrypt File" button.
4. Choose the source file to encrypt.
5. Choose the destination file for the encrypted output.
6. Optionally, check the "Compress Files" and "Shred Original File" checkboxes.
7. Click the "Encrypt File" button.

### Decrypt a File

1. Launch the Allcrypt GUI.
2. Enter the path to the USB drive in the provided field.
3. Click the "Decrypt File" button.
4. Choose the source file to decrypt.
5. Choose the destination file for the decrypted output.
6. Optionally, check the "Shred Original File" checkbox.
7. Click the "Decrypt File" button.

### Generate a New Key

1. Launch the Allcrypt GUI.
2. Enter the path to the USB drive in the provided field.
3. Click the "Generate New Key for this USB" button.
4. Enter a password for key encryption when prompted.
5. The new key will be generated and saved on the USB drive.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About Me:

1. My name is Pranav
2. Visit my [Github](github.com/pranavnasrani)
3. To look at source code on github and raise issues: [Allcrypt Source code](github.com/pranavnasrani/allcrypt)
