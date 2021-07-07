import os
import base64
import json
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from datetime import datetime

os.chdir(os.path.dirname(__file__))

# Import Key-Pairs
with open('sample-privkey.pem', 'r') as fd:
    signer = PKCS1_v1_5.new(RSA.importKey(fd.read()))

with open('sample-pubkey.pem', 'r') as fd:
    verifier_1 = PKCS1_v1_5.new(RSA.importKey(fd.read()))

# Import other Pub-Key
with open('testserver-pub.pem', 'r') as fd:
    verifier_2 = PKCS1_v1_5.new(RSA.importKey(fd.read()))

method = 'POST'
url = 'https://callback.example.com/04f12bfc'
content = json.dumps({'text': 'Hello world'})

# Encode content
content_bytes = content.encode()

content_sha256 = base64.b64encode(SHA256.new(content_bytes).digest())
content_sha256_decoded = content_sha256.decode()

# Datetime object containing current date and time in the format YYYY-MM-DD hh:mm:ss
now = datetime.now()
dt_string = now.strftime("%Y-%m-%d %H:%M:%S")
# print("date and time =", dt_string)

headers = {
    'Accept': 'application/vnd.mcash.api.merchant.v1+json',
    'Content-Type': 'application/json',
    'X-Settle-Merchant': '{merchant_id}',
    'X-Settle-User': '{api_user_id}',
    'X-Settle-Timestamp': dt_string,
    'X-Settle-Content-Digest': 'SHA256=' + content_sha256_decoded,
}

# Make all header names uppercase
headers = {k.upper(): v for k, v in headers.items()}

# Construct headers string for signature
sign_headers = ''
d = ''
for key, value in sorted(headers.items()):
    if not key.startswith('X-SETTLE-'):
        continue
    sign_headers += d + key + '=' + value
    d = '&'

# Construct signed message
sign_msg = '|'.join([method.upper(), url.lower(), sign_headers])
# print('sign_msg =', sign_msg)

# Encode signed message
sign_msg_bytes = sign_msg.encode()
# print('sign_msg_bytes =', sign_msg_bytes)

# Encode signature
rsa_signature = base64.b64encode(signer.sign(SHA256.new(sign_msg_bytes)))
rsa_signature_decoded = rsa_signature.decode()

# Construct Auth Header
rsa_auth_header = 'RSA-SHA256 ' + rsa_signature_decoded

# Test if verified, if not, raise an AssertionError.
assert verifier_1.verify(SHA256.new(sign_msg_bytes), base64.b64decode(rsa_signature)), 'Invalid signature'

# Add fancy colors to output
class bcolors:
    OKCYAN      =   '\033[96m'
    OKGREEN     =   '\033[92m'
    WARNING     =   '\033[93m'
    FAIL        =   '\033[91m'
    ENDC        =   '\033[0m'
    BOLD        =   '\033[1m'

print(f'{bcolors.BOLD}X-Settle-Content-Digest value is:{bcolors.ENDC} {bcolors.OKCYAN}{content_sha256_decoded}{bcolors.ENDC}')
print(f'{bcolors.BOLD}Headers part of signature message is:{bcolors.ENDC} {bcolors.OKCYAN}{sign_headers}{bcolors.ENDC}')
print(f'{bcolors.BOLD}Signature message is:{bcolors.ENDC} {bcolors.OKCYAN}{sign_msg}{bcolors.ENDC}')
print(f'{bcolors.BOLD}Authorization header for RSA-SHA256 is:{bcolors.ENDC} {bcolors.OKCYAN}{rsa_auth_header}{bcolors.ENDC}')

# Verify valid PKCS#1 v1.5 signatures (RSAVP1)
try:
    verifier_1.verify(SHA256.new(sign_msg_bytes), base64.b64decode(rsa_signature))
    print(f"First signature should be valid. {bcolors.OKGREEN}It is VALID.{bcolors.ENDC}")
except:
    print(f"First signature should be valid. {bcolors.FAIL} It is INVALID.{bcolors.ENDC}")

try:
    verifier_2.verify(SHA256.new(sign_msg_bytes), base64.b64decode(rsa_signature))
    print(f"Second signature should be invalid. {bcolors.FAIL}It is VALID.{bcolors.ENDC}")
except:
    print(f"Second signature should be invalid. {bcolors.OKGREEN} It is INVALID.{bcolors.ENDC}")

# Generate 1024-bit RSA key pair (private + public key) to use below
keyPair = RSA.generate(bits=1024)
pubKey = keyPair.publickey()
verifier_3 = PKCS115_SigScheme(pubKey)

try:
    verifier_3.verify(SHA256.new(sign_msg_bytes), base64.b64decode(rsa_signature))
    print(f"Third signature should be invalid. {bcolors.OKGREEN}It is VALID.{bcolors.ENDC}")
except:
    print(f"Third signature should be invalid. {bcolors.WARNING}It is INVALID.{bcolors.ENDC}")
