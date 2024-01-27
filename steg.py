import zlib
import base64
import hashlib
import os
import hmac
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet

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

def encrypt(data: bytes, secret_key: bytes, salt: bytes) -> bytes:
    # Derive the key
    key = derive_key(secret_key, salt)

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt the data
    cipher_text = cipher.encrypt(pad(data, AES.block_size))

    # Return the IV + cipher text
    return cipher.iv + cipher_text

def derive_key(secret_key: bytes, salt: bytes) -> bytes:
    # Use PBKDF2 to derive a key
    kdf = PBKDF2(secret_key, salt, dkLen=32, count=1000000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    return kdf

def encodeText(text: str, hidden_message: str, secret_key: bytes, salt: bytes) -> tuple:
    # Convert plain text and hidden message to binary
    plain_binary = textToBinary(text)
    hidden_binary = textToBinary(hidden_message)

    # Combine the binary strings
    combined_binary = plain_binary[:len(plain_binary)//2] + hidden_binary + plain_binary[len(plain_binary)//2:]

    # Apply Zero-Width Characters algorithm
    combined_zwc = zwcAlgorithm(combined_binary)

    # Encrypt using AES-256
    encrypted_result = encrypt(combined_zwc.encode(), secret_key, salt)

    # Compress the result
    compressed_result = zlib.compress(encrypted_result)

    # Convert the result to base64 for easy sharing
    encoded_message = base64.b64encode(compressed_result).decode()

    return encoded_message, salt

def decodeText(encodedMessage: str, secret_key: bytes, salt: bytes) -> str:
    # Decode base64
    compressed_result = base64.b64decode(encodedMessage)

    # Decompress the result
    encrypted_result = zlib.decompress(compressed_result)

    # Decrypt using AES-256
    decrypted_data = decrypt(encrypted_result, secret_key, salt)

    # Reverse Zero-Width Characters
    decrypted_data = zwcReverse(decrypted_data.decode())

    # Convert binary to plain text
    plain_text = binaryToText(decrypted_data)

    return plain_text

def decrypt(data: bytes, secret_key: bytes, salt: bytes) -> bytes:
    # Derive the key
    key = derive_key(secret_key, salt)

    # Extract the IV from the data
    iv = data[:AES.block_size]

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # Decrypt the data
    decrypted_data = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)

    return decrypted_data
def encodeMode() -> None:
    # Get input from the user
    text = input("Enter the text: ")
    hidden_message = input("Enter the hidden message: ")
    
    # Generate a random secret key
    secret_key = get_random_bytes(32)  # You can adjust the key size as needed
    
    salt = os.urandom(16)  # Generate a random salt

    # Encode the message
    encoded_message, salt = encodeText(text, hidden_message, secret_key, salt)

    print("\nEncoded Message:", encoded_message)
    print("Encryption Key:", base64.b64encode(secret_key).decode())
    print("Salt:", base64.b64encode(salt).decode())

    downloadEncodedTxtFile(encoded_message)

def decodeMode() -> None:
    # Get input from the user
    encoded_message = input("Enter the encoded message: ")
    secret_key = input("Enter the encryption key: ")
    salt = input("Enter the salt: ")

    # Convert string inputs to bytes
    secret_key = base64.b64decode(secret_key)
    salt = base64.b64decode(salt)

    # Decode the message
    decoded_text = decodeText(encoded_message, secret_key, salt)

    print("Decoded Text:", decoded_text)

# Main program
if __name__ == "__main__":
    # Get the mode from the user
    mode = input("Enter mode (encode/decode): ")
    selectMode(mode)
