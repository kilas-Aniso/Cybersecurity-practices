import re
import math
import hashlib
import sys

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = {"password", "123456", "qwerty", "abc123", "letmein", "welcome", "passw0rd"}

    def calculate_entropy(self, password):
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
            charset_size += 32

        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return entropy

    def check_common_passwords(self, password):
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        return password in self.common_passwords or hashed_password in self.common_passwords

    def check_password_strength(self, password):
        length_error = len(password) < 8
        digit_error = re.search(r"\d", password) is None
        uppercase_error = re.search(r"[A-Z]", password) is None
        lowercase_error = re.search(r"[a-z]", password) is None
        special_char_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None
        common_password_error = self.check_common_passwords(password)

        errors = sum([length_error, digit_error, uppercase_error, lowercase_error, special_char_error])
        entropy = self.calculate_entropy(password)

        if common_password_error:
            return "\033[91mVery Weak Password (Common Password) ❌\033[0m"
        elif entropy > 60:
            return "\033[92mVery Strong Password ✅\033[0m"
        elif errors == 0 and entropy > 40:
            return "\033[92mStrong Password ✅\033[0m"
        elif errors <= 2 and entropy > 30:
            return "\033[93mMedium Strength Password ⚠️\033[0m"
        else:
            return "\033[91mWeak Password ❌\033[0m"

    def run(self):
        while True:
            password = input("Enter your password (or type 'exit' to quit): ")
            if password.lower() == "exit":
                print("\033[94mExiting...\033[0m")
                sys.exit()
            print(self.check_password_strength(password))

if __name__ == "__main__":
    checker = PasswordStrengthChecker()
    checker.run()
