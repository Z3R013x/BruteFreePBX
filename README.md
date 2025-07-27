# Brute FreePBX

Python script I made to brute force a FreePBX, Hopefully it'll be more useful for you than it was for me xD


## Usage


python3 bruteipbx.py  -t http://targetfreepbx -u users.txt -p ~/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt -w 50 --proxy http://127.0.0.1:8080

-t stands for target
-u username or usernames file
-p password or passwords file
-w is workers count for ThreadPoolExecutor 

--proxy is optional argument if you'd like to use proxy

login path is automatically appended on -t, so don't worry about it

on success prints credentials and response text as well (sometimes I've had false positives)
