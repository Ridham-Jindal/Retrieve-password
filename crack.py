import hashlib
import re


def identify_hash_algorithm(hash_input):
    hash_types = {
        32: "md5",
        40: "sha1",
        56: "sha224",
        64: "sha256",
        96: "sha384",
        128: "sha512"
    }

    # Check if the hash length matches a known type
    hash_length = len(hash_input)
    if hash_length in hash_types:
        return hash_types[hash_length]

    # Regex-based checks for bcrypt, Argon2, crypt formats (these require external libraries in Python)
    if re.match(r"^\$2[abxy]?\$[0-9]{1,2}\$.{53}$", hash_input):
        return "bcrypt"  # bcrypt and Argon2 not natively in hashlib
    elif re.match(r"^\$argon2[i,d]\$.{0,}$", hash_input):
        return "argon2"
    elif re.match(r"^\$5\$.{0,}$", hash_input):
        return "sha256_crypt"
    elif re.match(r"^\$6\$.{0,}$", hash_input):
        return "sha512_crypt"

    return None  # Unknown hash type


def generate_hashes(file_path, hash_algorithm):
    try:
        # Open the file and read lines
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Hash each line using the identified algorithm
        print(f"Generating {hash_algorithm} hashes for each line in '{file_path}':")
        for line in lines:
            line = line.strip() 
            print(f"Trying :      {line}")
            if hash_algorithm in hashlib.algorithms_available:
                hash_obj = hashlib.new(hash_algorithm)
                hash_obj.update(line.encode('utf-8'))
                if hash_obj.hexdigest() is user_input:
                    print("-"*50)
                    print("*"*15, end="")
                    print("Password Cracked", end="")
                    print("*"*15)
                    print(f"Password: {line}")
                    quit()


            else:
                print(f"Hashing algorithm '{hash_algorithm}' is not supported by hashlib.")
                break
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Taking the input hash to identify if there is any matching hash
user_input = input("Enter the hash to identify: ").strip()
identified_algorithm = identify_hash_algorithm(user_input)

if identified_algorithm:
    generate_hashes("rockyou.txt", identified_algorithm)
else:
    print("Unable to identify a supported hash algorithm.")
