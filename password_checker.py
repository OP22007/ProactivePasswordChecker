import requests
import hashlib
import sys
import time
import re

SPECIAL_CHARACTERS = ".@!#$%^&*-_"

class User:
    def __init__(self, username, dob, pass_file):
        self.username = username
        self.dob = dob
        self.pass_file = pass_file
        self.passwords = []
        try:
            # Extract first and last names, handling cases with no '.'
            if '.' in self.username:
                self.fname, self.surname = self.username.split('.', 1)
            else:
                self.fname = self.username
                self.surname = ""
        except ValueError:
            self.fname = self.username
            self.surname = ""


def load_users():
    """Loads all users from the masterfile."""
    users = {}
    try:
        with open("masterfile.txt", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 3:
                    username, dob, pass_file = parts
                    users[username] = User(username, dob, pass_file)
    except FileNotFoundError:
        print("Error: masterfile.txt not found. Please create it.")
        sys.exit(1)
    return users

def load_passwords(user):
    """Loads up to 10 previous passwords for a given user."""
    try:
        with open(user.pass_file, "r") as f:
            user.passwords = [line.strip() for line in f.readlines()[:10]]
    except FileNotFoundError:
        print(f"Warning: Password file '{user.pass_file}' not found for user '{user.username}'. Assuming no previous passwords.")
        user.passwords = []

def save_passwords(user):
    """Saves the user's password list to their file."""
    try:
        with open(user.pass_file, "w") as f:
            for p in user.passwords:
                f.write(f"{p}\n")
    except IOError as e:
        print(f"Error saving password file: {e}")
        sys.exit(1)

def check_pwned_password(password):
    """Checks password against HIBP Pwned Passwords API using k-Anonymity."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        res = requests.get(url)
        if res.status_code != 200:
            print(f"Warning: Could not check HIBP API (Status code: {res.status_code}). Skipping this check.")
            return 0
        
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
    except requests.exceptions.RequestException as e:
        print(f"Warning: Network error checking HIBP API: {e}. Skipping this check.")
        return 0
    return 0

def longest_common_substring(s1, s2):
    """Finds the length of the longest common substring between two strings (case-insensitive)."""
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    max_len = 0
    for i in range(len(s1_lower)):
        for j in range(len(s2_lower)):
            temp_len = 0
            while (i + temp_len < len(s1_lower) and
                   j + temp_len < len(s2_lower) and
                   s1_lower[i + temp_len] == s2_lower[j + temp_len]):
                temp_len += 1
            if temp_len > max_len:
                max_len = temp_len
    return max_len

def is_password_valid(new_pass, user, attempt):
    """Validates the new password against all security rules."""
    violations = []

    # Rule 1: Length >= 12
    if len(new_pass) < 12:
        violations.append("Password does not contain a minimum of 12 characters.")

    # Rule 2, 3, 4, 5: Character types
    if not re.search(r'[A-Z]', new_pass): violations.append("Password does not contain at least one uppercase letter.")
    if not re.search(r'[a-z]', new_pass): violations.append("Password does not contain at least one lowercase letter.")
    if not re.search(r'\d', new_pass): violations.append("Password does not contain at least one digit.")
    if not any(c in SPECIAL_CHARACTERS for c in new_pass): violations.append("Password does not contain at least one of the allowed special characters.")

    # Rule 6: Similarity to previous passwords
    max_similarity = 0
    for old_pass in user.passwords:
        similarity = longest_common_substring(new_pass, old_pass)
        if similarity > max_similarity:
            max_similarity = similarity
    if max_similarity > 4:
        violations.append(f"Password contains {max_similarity} characters consecutively similar to one of the past passwords.")

    # Rule 7: Contains parts of username
    lower_pass = new_pass.lower()
    if user.fname and user.fname.lower() in lower_pass: violations.append("Password contains name portion of the username.")
    if user.surname and user.surname.lower() in lower_pass: violations.append("Password contains surname portion of the username.")

    # Rule 8: Contains consecutive digits from DOB
    dob_digits = "".join(filter(str.isdigit, user.dob))
    max_dob_match = 0
    for i in range(len(new_pass) - 3):
        substring = new_pass[i:i+4]
        if substring.isdigit() and substring in dob_digits:
            max_dob_match = 4 # Found a 4-digit match
            break
    if max_dob_match >= 4:
        violations.append(f"Password contains {max_dob_match} digits consecutively similar to the date of birth.")
    
    # NEW Rule 9: Check HIBP Database
    pwned_count = check_pwned_password(new_pass)
    if pwned_count > 0:
        violations.append(f"Warning: This password has appeared in a data breach {pwned_count:,} times and is not secure.")

    if not violations:
        return True, []
    
    # Print violations only on the first 3 attempts as per original logic
    if attempt <= 3:
        print("-" * 20)
        for v in violations:
            print(v)
        print("-" * 20)
        
    return False, violations

def backoff_timer(seconds):
    """A simple countdown timer."""
    for i in range(seconds, 0, -1):
        # Use carriage return and flush to create a dynamic single-line timer
        sys.stdout.write(f"\rWait for {i} seconds....")
        sys.stdout.flush()
        time.sleep(1)
    # Clear the line
    sys.stdout.write("\r" + " " * 30 + "\r")
    sys.stdout.flush()

def main():
    """Main application flow."""
    all_users = load_users()
    if not all_users:
        print("No users found in masterfile.txt. Exiting.")
        return

    # --- User Authentication ---
    username = input("Enter username: ")
    if username not in all_users:
        print("Username not found.")
        return
    
    current_user = all_users[username]
    load_passwords(current_user)
    
    if not current_user.passwords:
        print("No current password set for this user. Proceeding to password creation.")
    else:
        login_attempts = 0
        auth_success = False
        while login_attempts < 3:
            password_attempt = input("Enter password: ")
            if password_attempt == current_user.passwords[0]:
                print("Login Successful.")
                auth_success = True
                break
            else:
                login_attempts += 1
                print(f"Wrong password! ({3 - login_attempts} attempts left)")
        
        if not auth_success:
            print("Wrong password entered 3 times. Application exiting...")
            return

    # --- Password Change ---
    change_attempts = 0
    valid = False
    while change_attempts < 4:
        print(f"\nEnter your new password (attempt {change_attempts + 1}/4): ")
        new_password = input()
        
        is_valid, _ = is_password_valid(new_password, current_user, change_attempts + 1)
        
        if is_valid:
            print("Password changed successfully.")
            # Add new password to the front and keep list size to 10
            current_user.passwords.insert(0, new_password)
            current_user.passwords = current_user.passwords[:10]
            save_passwords(current_user)
            valid = True
            break
        else:
            change_attempts += 1
            if change_attempts == 4:
                break
            
            backoff_seconds = 2 ** (change_attempts + 2) # 8, 16, 32
            backoff_timer(backoff_seconds)
            
    if not valid:
        print("\nFailed to enter a valid password in 4 attempts.")

if __name__ == "__main__":
    main()
