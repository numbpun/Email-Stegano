import zlib
import base64
import hashlib
import os
import hmac
import time
import getpass  # Added for secure password input
# from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import getpass

# Constants
AES_BLOCK_SIZE = 16
AES_KEY_LENGTH = 32
SALT_LENGTH = 16

def selectMode(mode: str) -> None:
    if mode.lower() == "encode":
        encodeMode()
    elif mode.lower() == "decode":
        decodeMode()
    else:
        print("Invalid mode. Please choose 'encode' or 'decode'.")

def downloadEncodedTxtFile(encodedMessage: str) -> None:
    with open("encoded_message.txt", "w") as file:
        file.write(encodedMessage)
    print("Encoded message saved to encoded_message.txt")

def zwcAlgorithm(data: str) -> str:
    return ''.join([chr(8203 + int(bit)) for bit in data])

def zwcReverse(data: str) -> str:
    return ''.join(['1' if ord(char) - 8203 == 1 else '0' for char in data])

def textToBinary(plainText: str) -> str:
    binaryText = ''.join(format(ord(char), '08b') for char in plainText)
    return binaryText

def binaryToText(binaryText: str) -> str:
    text = ''.join([chr(int(binaryText[i:i+8], 2)) for i in range(0, len(binaryText), 8)])
    return text

def derive_key(secret_key: bytes, salt: bytes) -> bytes:
    # Using PBKDF2 to derive a key
    kdf = PBKDF2(secret_key, salt, dkLen=32, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    return kdf

def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = Fernet(base64.urlsafe_b64encode(key))
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt(data: bytes, key: bytes) -> bytes:
    cipher = Fernet(base64.urlsafe_b64encode(key))
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def encodeText(text: str, hidden_message: str, secret_key: bytes, salt: bytes) -> tuple:
    # Convert plain text and hidden message to binary
    plain_binary = textToBinary(text)
    hidden_binary = textToBinary(hidden_message)

    # Apply Zero-Width Characters algorithm
    zwc_encoding = zwcAlgorithm(hidden_binary)

    mergeTogether = plain_binary + zwc_encoding

    encrypted_result = encrypt(mergeTogether.encode(), secret_key)

    # Convert the result to base64 for easy sharing
    encoded_message = base64.b64encode(encrypted_result).decode()

    return encoded_message, salt.hex(), secret_key.hex()

def encodeMode() -> None:
    # Get input from the user
    text = input("Enter the plain text: ")
    hidden_message = input("Enter the hidden text: ")
    hidden_pass = input("Set the hidden password: ")
    confirm_pass = input("Confirm the hidden password: ")

    # Confirm the hidden password
    if hidden_pass != confirm_pass:
        print("Hidden passwords do not match. Please start again.")
        return

    # Generate a random salt
    salt = os.urandom(SALT_LENGTH)

    # Convert string inputs to bytes
    secret_key = derive_key(hidden_pass.encode(), salt)

    # Encode the message
    encoded_message, salt_hex, key_hex = encodeText(text, hidden_message, secret_key, salt)

    print("\nDone!\n")
    downloadEncodedTxtFile(encoded_message)

    print("Salt:", salt_hex)
    print("Encryption key:", key_hex)

def decodeText(encoded_message: str, secret_key: bytes, salt: bytes, decryption_password: str) -> str:
    # Derive the key using the decryption password and salt
    key = derive_key(decryption_password.encode('utf-8'), salt)

    # Decode the message
    try:
        decrypted_result = decrypt(base64.b64decode(encoded_message), key)
    except Exception as e:
        print(f"\nError during decoding: {e}")
        return ""

    # Reverse Zero-Width Characters
    decrypted_result = zwcReverse(decrypted_result.decode(errors='replace'))

    # Convert binary to plain text
    try:
        plain_text = binaryToText(decrypted_result)
    except Exception as e:
        print(f"\nError during text conversion: {e}")
        return ""

    return plain_text

def decodeMode():
    encoded_file = input("Enter the name of the encoded message file (e.g., encoded_message.txt): ")

    try:
        # Read the entire content of the file
        with open(encoded_file, "rb") as file:
            file_content = file.read()
            key = input("Enter the encryption key: ")
            salt = input("Throw the salt: ")
            print("Key and Salt Processing...")
 
            saltHex = bytes.fromhex(salt)
            key_hex = bytes.fromhex(key)
            print("Key and Salt Processed... Now decrypting... ")

        decrypted_text_bytes = decrypt(file_content, key_hex)
        print("Decrypted Bytes :",  decrypted_text_bytes)
        decryptedText = textToBinary(decrypted_text_bytes)

        print("\nHere you go!")
        print(f"Plain text: {decryptedText}")

        print("Have a nice Day!\n")
        time.sleep(2)
        hidden_pass = getpass.getpass("Enter the hidden pass: ")

        # # Decode the hexadecimal representation of the key
        # key_hex = bytes.fromhex(key)
        # saltHex = bytes.fromhex(salt)

        # Decoding logic
        try:
            decoded_text = decodeText(file_content, key_hex, saltHex, hidden_pass)

            # Display plain text
            print("\nHere you go!")
            print(f"Hidden Message: {decoded_text}")
        except Exception as e:
            print(f"\nError during decoding: {e}")

    except Exception as e:
        print(f"\nError reading encrypted message file: {e}")

# Function to extract hidden text
def extractHiddenText(data: str) -> str:
    hidden_binary = data[64:-64]
    hidden_text = binaryToText(hidden_binary)
    return hidden_text

# Main program
if __name__ == "__main__":
    # Get the mode from the user
    mode = input("Enter mode (encode/decode): ")
    selectMode(mode)
