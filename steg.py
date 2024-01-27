import zlib
import base64
import hashlib
import os
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet


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
    # Implement the Zero-Width Characters algorithm
    return ''.join([chr(8203 + int(bit)) for bit in data])

def zwcReverse(data: str) -> str:
    # Implement the reverse of Zero-Width Characters algorithm
    return ''.join(['1' if ord(char) - 8203 == 1 else '0' for char in data])

def textToBinary(plainText: str) -> str:
    binaryText = ''.join(format(ord(char), '08b') for char in plainText)
    return binaryText

def binaryToText(binaryText: str) -> str:
    text = ''.join([chr(int(binaryText[i:i+8], 2)) for i in range(0, len(binaryText), 8)])
    return text

def derive_key(secret_key: bytes, salt: bytes) -> bytes:
    # Use PBKDF2 to derive a key
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

    # Combine the binary strings
    combined_binary = plain_binary[:len(plain_binary)//2] + hidden_binary + plain_binary[len(plain_binary)//2:]

    # Apply Zero-Width Characters algorithm
    combined_zwc = zwcAlgorithm(combined_binary)

    # Encrypt using Fernet symmetric encryption
    encrypted_result = encrypt(combined_zwc.encode(), secret_key)

    # Compress the result
    compressed_result = zlib.compress(encrypted_result)

    # Convert the result to base64 for easy sharing
    encoded_message = base64.b64encode(compressed_result).decode()

    return encoded_message, salt

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
    encoded_message, salt = encodeText(text, hidden_message, secret_key, salt)

    print("\nDone!\n")
    downloadEncodedTxtFile(encoded_message)

def decodeText(encoded_message: str, secret_key: bytes, salt: bytes, decryption_password: str) -> str:
    # Derive the key using the decryption password and salt
    key = derive_key(decryption_password.encode('utf-8'), salt)

    # Decode the message
    decrypted_result = decrypt(base64.b64decode(encoded_message), key)

    # Reverse Zero-Width Characters
    decrypted_result = zwcReverse(decrypted_result.decode())

    # Convert binary to plain text
    plain_text = binaryToText(decrypted_result)

    return plain_text

def decodeMode():
    file_name = input("Enter the name of the encoded message file (e.g., encoded_message.txt): ")

    try:
        with open(file_name, "r") as file:
            encoded_text = file.read()
    except FileNotFoundError:
        print(f"File {file_name} not found.")
        return

    encryption_key = input("Enter the encryption key: ")

    try:
        # Allow the user 2 seconds to press Enter to enter the hidden password
        print("\nWaits for 2 seconds: User presses Enter once in order to enter the hidden password\n")
        time.sleep(2)
        print("Enter the hidden pass:")
        hidden_pass = input()  # Read the input directly
    except KeyboardInterrupt:
        print("\nOperation canceled.")
        return

    # Decoding logic
    try:
        # Decryption
        decrypted = base64.b64decode(encoded_text).decode('utf-8')
        salted_pass = (hidden_pass + encryption_key).encode('utf-8')
        hash_obj = hashlib.sha256(salted_pass)
        salt = hash_obj.hexdigest()[:16]
        key = hashlib.pbkdf2_hmac('sha256', salted_pass, salt.encode('utf-8'), 100000)
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(decrypted.encode('utf-8')), AES.block_size).decode('utf-8')

        # Extract hidden text
        hidden_text = decrypted_text.split("Hidden Text: ")[1]
        decoded_text = decrypted_text.split("Hidden Text: ")[0]

        print("\nHere you go!")
        print(f"Plain text: {decoded_text}")
        print(f"Hidden Text: {hidden_text}")
    except Exception as e:
        print(f"\nError during decoding: {e}")


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
