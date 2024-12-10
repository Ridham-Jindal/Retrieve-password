import re
import os
import hashlib
import base64
from passlib.hash import bcrypt, sha256_crypt, sha512_crypt

def identify_hash_algorithm(hash_input):
    """
    Identify the type of hashing algorithm based on hash characteristics.
    """
    if re.match(r"^\$2[abxy]?\$[0-9]{1,2}\$.{53}$", hash_input):
        return "bcrypt"
    elif re.match(r"^\$5\$.{0,}$", hash_input):
        return "sha256_crypt"
    elif re.match(r"^\$6\$.{0,}$", hash_input):
        return "sha512_crypt"
    elif re.match(r"^\$y\$[0-9]+\$.{0,}$", hash_input):
        return "yescrypt"
    elif len(hash_input) in {32, 40, 56, 64, 96, 128}:
        hash_types = {
            32: "md5",
            40: "sha1",
            56: "sha224",
            64: "sha256",
            96: "sha384",
            128: "sha512"
        }
        return hash_types[len(hash_input)]
    return None

#passlib doesnot support yescrypt algorithm so we have created yescrypt hash generator for handling this algorithm
def generate_yescrypt_hash(password, salt, n=16384, r=8, p=1, hash_len=32):
    """
    Generate a Yescrypt-style hash for a given password.
    """
    key = hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        maxmem=0,
        dklen=hash_len,
    )
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    key_b64 = base64.b64encode(key).decode("utf-8")
    return f"$y${n}${salt_b64}${key_b64}"

def verify_yescrypt_hash(password, input_hash):
    """
    Verify a password against a Yescrypt-style hash.
    """
    try:
        parts = input_hash.split('$')
        n = int(parts[2])
        salt = base64.b64decode(parts[3])
        expected_hash = parts[4]
        
        computed_hash = generate_yescrypt_hash(password, salt, n=n).split('$')[4]
        return computed_hash == expected_hash
    except Exception as e:
        print(f"Error verifying Yescrypt hash: {e}")
        return False

def generate_and_match_hashes(file_path, hash_algorithm, input_hash):
    """
    Generate hashes from rockyou.txt and compare them to the input hash.
    """
    try:
        if hash_algorithm == "sha512_crypt" and not re.match(r"^\$6\$.*\$.*", input_hash):
            print("Error: The input hash does not match the expected sha512_crypt format.")
            return

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                password = line.strip()

                if hash_algorithm in hashlib.algorithms_available:
                    hash_obj = hashlib.new(hash_algorithm)
                    hash_obj.update(password.encode('utf-8'))
                    if hash_obj.hexdigest() == input_hash:
                        print(f"Password found: {password}")
                        return
                elif hash_algorithm == "bcrypt" and bcrypt.verify(password, input_hash):
                    print(f"Password found: {password}")
                    return
                elif hash_algorithm == "sha256_crypt" and sha256_crypt.verify(password, input_hash):
                    print(f"Password found: {password}")
                    return
                elif hash_algorithm == "sha512_crypt" and sha512_crypt.verify(password, input_hash):
                    print(f"Password found: {password}")
                    return
                elif hash_algorithm == "yescrypt":
                    if verify_yescrypt_hash(password, input_hash):
                        print(f"Password found: {password}")
                        return

        print("No matching password found.")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    user_input = input("Enter the hash to identify: ").strip()
    identified_algorithm = identify_hash_algorithm(user_input)

    if identified_algorithm:
        print(f"Identified Algorithm: {identified_algorithm}")
        generate_and_match_hashes("rockyou.txt", identified_algorithm, user_input)
    else:
        print("Unable to identify a supported hash algorithm.")
