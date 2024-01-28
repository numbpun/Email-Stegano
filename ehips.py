import os
import colorama
import pyperclip
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyfiglet
from PIL import Image
from colorama import Fore, init
from asciimatics.screen import Screen
from tabulate import tabulate
import platform

colorama.init()
init(autoreset=True)

GREEN = Fore.GREEN
RESET = Fore.RESET
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN 
RED = Fore.RED
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

def clear_screen():
    # Clear the screen based on the platform
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')


def to_base(num, b, numerals='0123456789abcdefghijklmnopqrstuvwxyz'):
    return ((num == 0) and numerals[0]) or (to_base(num // b, b, numerals).lstrip(numerals[0]) +
        numerals[num % b])

def encode_text():
    print(f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter message to send: ", end="")
    merge = input()
    print(f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter hidden: ", end="")
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

    print(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Choose ZWC option"],
                    [f"{Fore.LIGHTYELLOW_EX}1 - Encode"],
                    [f"{Fore.LIGHTYELLOW_EX}2 - Decode"],
                    [f"{Fore.LIGHTYELLOW_EX}3 - Send Email"],
                    [f"{Fore.LIGHTYELLOW_EX}4 - Decode Email"]], headers=['Options']))
    
    option = int(input())
    
    if option == 1:
        encoded_message, merge = encode_text()
    elif option == 2:
        print(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter message to decode"]], headers=['Options']))
        message = input()
        print(f"{GREEN}[+]{RESET} Decoded Message:  {decode_text(message)}")
        return
    elif option == 3:
        if encoded_message is None:
            print(tabulate([[f"{RED}[!]{RESET} Encode a message first before sending an email."]], headers=['Options']))
            return

        sender_email = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter sender's email"]], headers=['Options']))
        sender_password = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter sender's password"]], headers=['Options']))
        receiver_email = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter receiver's email"]], headers=['Options']))
        subject = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter email subject"]], headers=['Options']))
        
        # Read email body from an existing text file
        body_file_path = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter path to email body text file"]], headers=['Options']))
        with open(body_file_path, 'r') as file:
            body = file.read()

        # Save the encoded message to a file
        with open('encoded_message.txt', 'w') as encoded_file:
            encoded_file.write(encoded_message)

        # Send the email with the attached file
        send_email(sender_email, sender_password, receiver_email, subject, body, attachment_path='encoded_message.txt')
        print(tabulate([[f"{GREEN}[+]{RESET} Email sent with hidden message."]], headers=['Options']))
    elif option == 4:
        decode_email()

def decode_email():
    print(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter path to the email text file"]], headers=['Options']))
    email_file_path = input()
    
    try:
        with open(email_file_path, 'r') as file:
            encoded_message = file.read()
        print(tabulate([[f"{GREEN}[+]{RESET} Decoded Message:  {decode_text(encoded_message)}"]], headers=['Options']))
    except FileNotFoundError:
        print(tabulate([[f"{RED}[!]{RESET} File not found. Please make sure the file exists in the current directory."]], headers=['Options']))
    except Exception as e:
        print(tabulate([[f"{RED}[!]{RESET} An error occurred: {e}"]], headers=['Options']))



def display_menu():
    clear_screen()
    print(tabulate([[f"{Fore.CYAN}[{MIDDLE_DOT}]{RESET} Choose ZWC option"],
                    [f"{Fore.LIGHTYELLOW_EX}1 - Encode"],
                    [f"{Fore.LIGHTYELLOW_EX}2 - Decode"],
                    [f"{Fore.LIGHTYELLOW_EX}3 - Send Email"],
                    [f"{Fore.LIGHTYELLOW_EX}4 - Decode Email"],
                    [f"{Fore.LIGHTYELLOW_EX}5 - Quit"]], headers=['Options']))
    return int(input())

def menu():
    while True:
        option = display_menu()

        if option == 1:
            encoded_message, merge = encode_text()
        elif option == 2:
            print(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter message to decode"]], headers=['Options']))
            message = input()
            print(f"{GREEN}[+]{RESET} Decoded Message:  {decode_text(message)}")
        elif option == 3:
            send_email_option()
        elif option == 4:
            decode_email()
        elif option == 5:
            print(f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Exiting... Goodbye!")
            break
        else:
            print(f"{RED}[!]{RESET} Invalid option. Please choose a valid option.")

def send_email_option():
    global encoded_message  # Use the global keyword to reference the outer variable

    if encoded_message is None:
        print(tabulate([[f"{RED}[!]{RESET} Encode a message first before sending an email."]], headers=['Options']))
        return

    sender_email = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter sender's email"]], headers=['Options']))
    sender_password = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter sender's password"]], headers=['Options']))
    receiver_email = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter receiver's email"]], headers=['Options']))
    subject = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter email subject"]], headers=['Options']))
    
    # Read email body from an existing text file
    body_file_path = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Enter path to email body text file"]], headers=['Options']))
    with open(body_file_path, 'r') as file:
        body = file.read()

    # Save the encoded message to a file
    with open('encoded_message.txt', 'w') as encoded_file:
        encoded_file.write(encoded_message)

    # Send the email with the attached file
    send_email(sender_email, sender_password, receiver_email, subject, body, attachment_path='encoded_message.txt')
    print(tabulate([[f"{GREEN}[+]{RESET} Email sent with hidden message."]], headers=['Options']))

if __name__ == '__main__':
    print("")
    result = pyfiglet.figlet_format("E H I P S", font="alligator", width=100)
    print(f"{Fore.CYAN}{result}{RESET}")
    print("")
    
    a = True
    while a:
        command = input(tabulate([[f"{Fore.LIGHTYELLOW_EX}[{MIDDLE_DOT}]{RESET} Are you ready? (Yes/No): \n "]], headers=['Options']))
        cmd_splitted = command.split(' ', 1)

        if cmd_splitted[0].lower() == "yes":
            menu()
        else:
            print(f"\n{Fore.LIGHTYELLOW_EX}╭─ Ready whenever you are! ──────────────────────────────────────────────╮")
            print(f"{Fore.LIGHTYELLOW_EX}│ {RESET}No rush! Feel free to run me again whenever you're ready.              {Fore.LIGHTYELLOW_EX}│")
            print(f"{Fore.LIGHTYELLOW_EX}│ {RESET}If you have any questions or need assistance, I'm here to help!        {Fore.LIGHTYELLOW_EX}│")
            print(f"{Fore.LIGHTYELLOW_EX}│ {RESET}Have a fantastic day!                                                  {Fore.LIGHTYELLOW_EX}│")
            print(f"{RESET}{Fore.LIGHTYELLOW_EX}╰────────────────────────────────────────────────────────────────────────╯")
            a = False
