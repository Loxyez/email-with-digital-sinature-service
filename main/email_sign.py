import smtplib
import ssl
import imaplib
import email
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import time
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import base64
import re
from Crypto.PublicKey import RSA
from Crypto.IO import PEM

# Hyper Parameter
length = 1024
load_dotenv()

def generate_key():
    """
    This function generates a new RSA key pair and saves it to the disk.
    """
    
    private_key = RSA.generate(length, Random.new().read)
    public_key = private_key.publickey()
    
    with open("./private_key.pem", "wb") as key_file:
        key_file.write(private_key.exportKey())
        
    with open("./public_key.pem", "wb") as key_file:
        key_file.write(public_key.exportKey())

def sign_email(msg):
    """
    This function signs an email message with the sender's private key.
    """
    with open("./private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    return base64.b64encode(private_key.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256()))

def encrypt(rsa_publickey, plain_text):
    cipher = PKCS1_OAEP.new(rsa_publickey)
    ciphertext = cipher.encrypt(plain_text)
    plaintext = base64.b64encode(ciphertext)
    return plaintext

def decrypt(rsa_privatekey, b64cipher):
    """
    This function decrypts the message using the recipient's private key.
    """
    decoded_ciphertext = base64.b64decode(b64cipher)
    cipher = PKCS1_OAEP.new(rsa_privatekey)
    plaintext = cipher.decrypt(decoded_ciphertext)
    return plaintext

def verify_signature(msg, signature, public_key):
    """
    This function verifies the digital signature of an email message
    using the sender's public key.
    """
    try:
        signature_bytes = base64.b64decode(signature)
    except binascii.Error:
        return "Error: Invalid base64-encoded string"
    
    return public_key.verify(msg, (int(signature_bytes),))


def send_email(receiver, subject, body):
    """
    This function sends an email to the recipient using SMTP.
    """
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = os.getenv("sender_email")
    sender_password = os.getenv("sender_password")

    # Create a secure SSL context
    context = ssl.create_default_context()

    # Sign the message
    signature = sign_email(body)
    
    message = f"{body}\n\nSignature: {signature}"

    # Try to log in to server and send email
    try:
        server = smtplib.SMTP_SSL(smtp_server, port, context=context)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver, message)
        print("Email sent!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.quit()

def receive_email(message, sig):
    """
    This function receives emails from the recipient's mailbox using IMAP.
    """
    imap_server = "imap.gmail.com"

    # Login to the server and select the inbox folder
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(os.getenv("receiver_email"), os.getenv("receiver_password"))
    mail.select("inbox")

    # Search for emails from the specified sender
    typ, data = mail.search(None, "ALL")
    
    # print(len(data[0].split()))
    
    for num in reversed(data[0].split()):
        typ, data = mail.fetch(num, "(RFC822)")

        # Parse the email message
        
        with open("./public_key.pem", "rb") as key_file:
            public_key = key_file.read()
            
        with open("./private_key.pem", "rb") as key_file:
            private_key = key_file.read()
        
        verify = verify_signature(sig, message, public_key)
        
        public_key_obj = RSA.importKey(public_key)
        private_key_obj = RSA.importKey(private_key)
        enc_msg = encrypt(public_key_obj, message.encode('utf-8'))
        deco = decrypt(private_key_obj, enc_msg)
        if verify:
            mail.close()
            mail.logout()
            return "Signature is valid", deco.decode('utf-8')
        else:
            mail.close()
            mail.logout()
            return "Signature is invalid", None
