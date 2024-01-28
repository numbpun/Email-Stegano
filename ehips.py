import os
import colorama
import pyperclip
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyfiglet

colorama.init()

GREEN = colorama.Fore.GREEN
RESET = colorama.Fore.RESET
YELLOW = colorama.Fore.YELLOW
RED = colorama.Fore.RED
MIDDLE_DOT = '\u00b7'
ZERO_WIDTH_SPACE = '\u200b'
ZERO_WIDTH_NON_JOINER = '\u200c'
ZERO_WIDTH_JOINER = '\u200d'
LEFT_TO_RIGHT_MARK = '\u200e'
RIGHT_TO_LEFT_MARK = '\u200f'

padding = 11

zero_space_symbols = [
    ZERO_WIDTH_SPACE,
    ZERO_WIDTH_NON_JOINER,
    ZERO_WIDTH_JOINER,
]

def to_base(num, b, numerals='0123456789abcdefghijklmnopqrstuvwxyz'):
    return ((num == 0) and numerals[0]) or (to_base(num // b, b, numerals).lstrip(numerals[0]) +
        numerals[num % b])

def encode_text():
    print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter message to send: ", end="")
    merge = input()
    print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter hidden: ", end="")
    message = input()
    encoded = LEFT_TO_RIGHT_MARK
    for message_char in message:
        code = '{0}{1}'.format('0' * padding, int(str(to_base(
            ord(message_char), len(zero_space_symbols)))))
        code = code[len(code) - padding:]
        for code_char in code:
            index = int(code_char)
            encoded = encoded + zero_space_symbols[index]

    encoded += RIGHT_TO_LEFT_MARK
    print(f"{GREEN}[+]{RESET} Encoded message copied to clipboard. {GREEN}[+]{RESET}")
    print("Encoded Text: ", merge)
    pyperclip.copy(encoded)
    return encoded, merge

def decode_text(encoded_message):
    extract_encoded_message = encoded_message.split(LEFT_TO_RIGHT_MARK)[1]
    message = extract_encoded_message
    extract_encoded_message = message.split(RIGHT_TO_LEFT_MARK)[0]
    encoded = ''
    decoded = ''

    for message_char in message:
        if message_char in zero_space_symbols:
            encoded = encoded + str(zero_space_symbols.index(message_char))

    cur_encoded_char = ''

    for index, encoded_char in enumerate(encoded):
        cur_encoded_char = cur_encoded_char + encoded_char
        if index > 0 and (index + 1) % padding == 0:
            decoded = decoded + chr(int(cur_encoded_char, len(zero_space_symbols)))
            cur_encoded_char = ''

    return decoded

def send_email(sender_email, sender_password, receiver_email, subject, body, attachment_path=None):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    if attachment_path:
        with open(attachment_path, 'r') as attachment:
            attachment_content = MIMEText(attachment.read())
            attachment_content.add_header('Content-Disposition', 'attachment', filename='encoded_message.txt')
            msg.attach(attachment_content)

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

encoded_message = None


def email_steganography():
    global encoded_message  # Use the global keyword to reference the outer variable

    print("")
    print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Choose ZWC option (1 - Encode / 2 - Decode / 3 - Email): ", end="")
    option = int(input().lower())
    
    if option == 1:
        encoded_message, merge = encode_text()
    elif option == 2:
        print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter message to decode: ", end="")
        message = input()
        print(f"{GREEN}[+]{RESET} Decoded Message:  " + decode_text(message))
        return
    elif option == 3:
        if encoded_message is None:
            print(f"{RED}[!]{RESET} Encode a message first before sending an email.")
            return

        sender_email = input(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter sender's email: ")
        sender_password = input(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter sender's password: ")
        receiver_email = input(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter receiver's email: ")
        subject = input(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter email subject: ")
        
        # Read email body from an existing text file
        body_file_path = input(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter path to email body text file: ")
        with open(body_file_path, 'r') as file:
            body = file.read()

        # Save the encoded message to a file
        with open('encoded_message.txt', 'w') as encoded_file:
            encoded_file.write(encoded_message)

        # Send the email with the attached file
        send_email(sender_email, sender_password, receiver_email, subject, body, attachment_path='encoded_message.txt')
        print(f"{GREEN}[+]{RESET} Email sent with hidden message. {GREEN}[+]{RESET}")
    else:
        print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter path to the email text file: ", end="")
        email_file_path = input()
        decode_email(email_file_path)

def decode_email():
    print(f"{YELLOW}[{MIDDLE_DOT}]{RESET} Enter filename containing encoded message: ", end="")
    filename = input()

    try:
        with open(filename, 'r') as file:
            encoded_message = file.read()
            decoded_message = decode_text(encoded_message)
            print(f"{GREEN}[+]{RESET} Decoded Message:  {decoded_message}")
    except FileNotFoundError:
        print(f"{RED}[!]{RESET} File not found: {filename}")

if __name__ == '__main__':
    print("")
    result = pyfiglet.figlet_format("E H I P S", font="alligator", width=100)
    print(result) 
    print("")
    
    while True:
        command = input("Are you ready? (Yes/No): ")
        cmd_splitted = command.split(' ', 1)

        if cmd_splitted[0] == "Yes":
            email_steganography()
