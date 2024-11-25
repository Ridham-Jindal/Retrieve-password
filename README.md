# Retrieve-password
A script to retrieve passwords from a Linux machine and brute force it to retrieve the password.

Steps to do it
1. The passwords in the Linux file are stored in /etc/shadow file in Linux.
2. We have made one shell script which is copying shadow file to copy.txt.
3. Then we will parse the copy.txt file in which hash values will be stored.
4. This file will be passed to python file and then we will determine which hash algorithm is being used.
5. Then we will use "rockyou.txt" file, downloaded from GitHub containing a lot of passwords, we will hash those passwords by applying various filters and the same hash algorithm then we will match this hash value with the hash value stored in copy.txt file. 
If hash matches then we will get the password and hence password is cracked :).
