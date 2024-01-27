import argparse
import zlib
from aes_256 import encrypt, decrypt  # Assuming aes_256.py is in the same directory

# Functions needed
# Encode function
# Decode function
# Mode function - Function to prompt the user to enter encode or decode mode
# Save to file function

def encodeText(plainText: str, hiddenText: str) -> str:
    print("Hidden Text (Visible): ", hiddenText)
    # Convert the hidden into Binary using its ASCII values
    hidden = ''.join(format(ord(i), '08b') for i in hiddenText)
    print("Hidden Text: ", hidden)
    # Convert binary into ZWC (Zero-Width Characters)
    zwc_encode = hidden.replace('0', '\u200C').replace('1', '\u200D')
    print("Zero Width Characters Implemented: ", zwc_encode)

    # Combine plaintext and ZWC-encoded data
    combined_text = plainText + zwc_encode
    
    # Convert the combined text to bytes
    combined_bytes = combined_text.encode()

    # Generate a random salt for key derivation
    salt = b'\x9d(\xf5\xc3N{\x13}\xd2\x84\x94\xc1\x91\xd8M6'

    # Encrypt the combined text using AES-256 algorithm
    encrypted_result = encrypt(combined_bytes, "your_secret_key", salt)
    print("\nEncrypted result using AES-256: ", encrypted_result)
    print("\n")

    # Check if the .txt file is larger or smaller than another file containing just plaintext data
    if len(encrypted_result) != len(combined_bytes):
        print("Size difference detected. Applying compression algorithm to prevent detection...")
        compressed_result = zlib.compress(encrypted_result)
        print("File Compressed!")
        print(compressed_result)
        print("\n")
    else:
        return compressed_result


def decode(receivedEmailText: str, secretKey: str) -> str:
    # Decompress the data
    decompressed_data = zlib.decompress(receivedEmailText).decode()

    # Extract encrypted ZWC data
    encrypted_zwc = decompressed_data[len(secretKey):]

    # Generate the same salt used during encoding
    salt = b'\x9d(\xf5\xc3N{\x13}\xd2\x84\x94\xc1\x91\xd8M6'

    # Decrypt the ZWC data
    decrypted_zwc_data = decrypt(encrypted_zwc, "your_secret_key", salt)

    # Convert the ZWC data back to binary
    binary_data = decrypted_zwc_data.replace('\u200C', '0').replace('\u200D', '1')

    # Convert binary to plaintext
    plaintext = ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))

    return plaintext


def selectMode(mode: str) -> str:
    # Prompt the user for the mode
    # If the user wants to go to encode mode
        # Go to the encode function
    # Else if user wants to go to decode mode, then direct the user for the decode mode
    pass

def downloadEncodedTxtFile(encodedMessage: str):
    # Name is self-explanatory
    pass

# Helper functions needed
    # 1. ZWC Algorithm function
    # 2. ZWC Reverse
    # 3. PlainText to ASCII to Binary
    # 4. Binary to ASCII to PlainText 

if __name__ == "__main__":
     str1 = "My name is Jainam Kashyap"
     str2 = "My google account password is JohnDoe123"
     (encodeText(str1, str2))