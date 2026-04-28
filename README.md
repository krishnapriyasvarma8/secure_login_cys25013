# Secure Login System

A secure login and registration system built with Python and Flask, implementing bcrypt password hashing, credential stuffing attack simulation with rate limiting and account lockout, and TOTP based two factor authentication using pyotp.

## Tasks

### Task 1 - Secure Login with bcrypt
- Login and registration system built with Flask
- Passwords hashed using bcrypt before storing in database
- Plaintext passwords never stored

### Task 2 - Credential Stuffing Attack and Defense
- Simulated credential stuffing attack using rockyou.txt wordlist
- Attack script tries passwords automatically against login page
- Defense implemented using rate limiting (5 attempts per minute)
- Account lockout after 5 failed attempts for 10 minutes

### Task 3 - TOTP Based 2FA
- Two factor authentication added using pyotp
- QR code generated on registration for Google/Microsoft Authenticator
- OTP verified on every login after password check
- Wrong OTP and replay attacks are rejected

## Files
- `app_before.py` - Task 1 - Basic login with bcrypt, no defenses
- `app.py` - Task 2 - Added rate limiting and account lockout
- `app_qr.py` - Task 3 - Added TOTP based 2FA
- `attack_multiple.py` - Attack script for multiple users
- `attack_single.py` - Attack script for single user
- `database.py` - Database setup for Task 1 and 2
- `database_qr.py` - Database setup for Task 3 with 2FA support
- `templates/` - HTML pages for all tasks

## Installation
```bash
pip install flask bcrypt flask-limiter pyotp qrcode[pil] requests
```

## How to Run
```bash
# Task 1
python app_before.py

# Task 2
python app.py

# Task 3
python app_qr.py
```
