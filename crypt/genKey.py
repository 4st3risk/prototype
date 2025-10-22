import hashlib
from random import randint

secret_key = randint(1,999999999)
hash = hashlib.sha256()
data = str(secret_key).encode('utf-8')
hash.update(data)
hex = hash.hexdigest()

print(f"Key is {hex}")

