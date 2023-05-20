import bcrypt
import hidden

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def compare_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

hashed_password = hash_password(hidden.passwords[1]["password"])
hashed_password2 = hash_password(hidden.passwords[2]["password"])

print(hashed_password)
print(hashed_password2)
print(compare_password(hashed_password, hashed_password2))

print(type(hashed_password))

# convert bytes to string
def bytes_to_string(bytes):
    return bytes.decode('utf-8')

# convert string to bytes
def string_to_bytes(string):
    return string.encode('utf-8')

print(bytes_to_string(hashed_password))
print(type(bytes_to_string(hashed_password)))


