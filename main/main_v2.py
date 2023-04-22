import smtplib
import ssl
import imaplib
import email
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import time
import re


def generate_key():
    """
    This function generates a new RSA key pair and saves it to the disk.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Save the private key to disk
    with open("./main/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save the public key to disk
    with open("./main/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def sign_email(msg):
    """
    This function signs an email message with the sender's private key.
    """
    with open("./main/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    msg = msg.encode("utf-8")

    signature = private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(msg, signature, public_key):
    """
    This function verifies the digital signature of an email message
    using the sender's public key.
    """
    msg = msg.encode("utf-8")

    try:
        public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


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

    # Create the message
    message = f"Subject: {subject}\n\n{body}"

    # Sign the message
    signature = sign_email(message)

    # Load the private key
    with open("./main/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Add the digital signature to the message
    message += f"\n\nSignature:{base64.b64encode(signature).decode('utf-8')}"
    message += f"\n\nPublic-Key:{base64.b64encode(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode('utf-8')}"

    # Try to log in to server and send email
    try:
        server = smtplib.SMTP_SSL(smtp_server, port, context=context)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver, message)
        print("Email sent!")
        time.sleep(10)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.quit()

def receive_email(receiver):
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
        msg = email.message_from_bytes(data[0][1])
        Signature = re.findall("Signature:(.*)", msg.get_payload())
        Public = re.findall("Public-Key:(.*)", msg.get_payload())
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if content_type == "text/plain" and "attachment" not in content_disposition:
                    body = part.get_payload(decode=True).decode("utf-8")
                    break
        else:
            body = msg.get_payload(decode=True).decode("utf-8")

        # Extract the digital signature and public key from the message
        signature = base64.b64decode(Signature[0])
        public_key_bytes = base64.b64decode(Public[0])
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        print(f"Signature: {signature}")
        print(f"Public Key: {public_key_bytes}")
        
        # Verify the digital signature of the message
        if verify_signature(body, signature, public_key):
            print("Message verified!")
            print(f"From: {msg['From']}")
            print(f"Subject: {msg['Subject']}")
            print(f"Body: {body}")
        else:
            print("Message could not be verified.")
        if msg['From'] == os.getenv("sender_email").lower():
            break

    mail.close()
    mail.logout()

if __name__ == "__main__":
    # Generate a new RSA key pair
    generate_key()
    
    load_dotenv()
    
    # Send an email
    receiver_email = os.getenv("receiver_email")
    subject = "I have to go to toilet"
    body = "If you read this you got yeeted."
    send_email(receiver_email, subject, body)
    
    receive_email(receiver_email)
