Ridham Jindal(2021UCS0111)
Arooshi Jain(2021UEE0131)

Write a script to retrieve passwords from a Linux machine and brute force it to retrieve the password.

Steps to use the code:-

1. The passwords in the Linux file are stored in /etc/shadow file in Linux.
2. We have made one shell script "copy.sh" which is copying shadow file to copy.txt .
3. Now, we have hash of stored passwords for different users, now copy the hash which you want to dcrypt.
4. Open the python file i.e."crack.py".
5. First download the necessary libraries like hashlib, passlib by using the command -> pip install "name_of_library"
6. Now execute the code.
7. The code will ask for the input of hashed password. Paste the hashed password of the user here and press Enter.
8. It will identify the hashing algorithm and then will give you the decrypted password and hence password is cracked.


How the code is working?
1. Now the code is using file "rockyou.text" which contains a numerous amount of passwords which are being commonly used by different users.
2. First it identifies the hashing algorithm.
3. Then based on this algorithm, it hashes the passwords in the file "rockyou.txt" and then matches it with the hashed password provided as input.
4. If there is a match then it returns the dcrypted password.


Supported hashing algorithms:
- bcrypt
- sha256_crypt
- sha512_crypt
- yescrypt