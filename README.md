<h1>RSA Encryption Algorithm</h1>
<p>This code generates a simple implementation of the RSA encryption algorithm to encrypt a message. RSA is an asymmetric encryption algorithm that relies on the difficulty of factoring large integers to ensure secure communication.</p>

<h3>Usage</h3>
<p>The code takes two arguments from the command line, the message to be encrypted and the number of bits in the generated keys. If no arguments are given, it uses a default message "Hello World" and sets the key size to 60 bits.

To run the code, execute the following command:</p>

```
python main.py [message] [key_size]
```

<p>where message is the message to be encrypted (optional) and key_size is the number of bits in the generated keys (optional).</p>
<hr>

<h3>Implementation</h3>
<p>The code first generates two large random prime numbers p and q, calculates their product n, and computes Euler's totient function PHI of n. The variable v is set to 65537, which is commonly used as a public exponent in RSA encryption. The variable s is the modular inverse of v with respect to PHI, and D is the message converted to a long integer using the UTF-8 encoding.

The message is encrypted by first computing S = D^s (mod n), then res = S^v (mod n), which yields the ciphertext. The private key s must be kept secret, while the public key (n,v) can be shared with others for encrypting messages.</p>
<hr>

<h3>Disclaimer</h3>
<p>This implementation is for educational purposes only and should not be used for real-world encryption. It is vulnerable to various attacks such as chosen-ciphertext attacks, padding oracle attacks, and side-channel attacks. It also lacks important features such as padding, which can compromise its security even further.</p>
