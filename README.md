<h1>Email Signature Verification System</h1>
<p>This is a simple system to send and receive emails with a digital signature to verify their authenticity. The system uses Python and the FastAPI framework for the backend and Google's SMTP and IMAP email servers for sending and receiving emails.</p>

<h3>Installation and Setup</h3>

1.Clone the repository to your local machine using the command: git clone https://github.com/username/repo-name.git
2.Navigate to the project directory and create a virtual environment: python3 -m venv env
3.Activate the virtual environment: source env/bin/activate
4.Install the required packages: pip install -r requirements.txt
5.Create a .env file in the project directory and add the following environment variables:
<li>sender_email: the email address of the sender</li>
<li>sender_password: the password for the sender's email account</li>
<li>receiver_email: the email address of the recipient</li>
<li>receiver_password: the password for the recipient's email account</li>
Run the server: ```uvicorn main:app --host 0.0.0.0 --reload```

<p>where message is the message to be encrypted (optional) and key_size is the number of bits in the generated keys (optional).</p>
<hr>

<h3>Implementation</h3>
<p>The code first generates two large random prime numbers p and q, calculates their product n, and computes Euler's totient function PHI of n. The variable v is set to 65537, which is commonly used as a public exponent in RSA encryption. The variable s is the modular inverse of v with respect to PHI, and D is the message converted to a long integer using the UTF-8 encoding.

The message is encrypted by first computing S = D^s (mod n), then res = S^v (mod n), which yields the ciphertext. The private key s must be kept secret, while the public key (n,v) can be shared with others for encrypting messages.</p>
<hr>

<h3>Disclaimer</h3>
<p>This implementation is for educational purposes only and should not be used for real-world encryption. It is vulnerable to various attacks such as chosen-ciphertext attacks, padding oracle attacks, and side-channel attacks. It also lacks important features such as padding, which can compromise its security even further.</p>
