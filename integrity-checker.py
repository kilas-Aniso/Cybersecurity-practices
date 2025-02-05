import hashlib
import os
import tkinter as tk
from tkinter import filedialog

class FileIntegrityChecker:
    def __init__(self):
        self.hash_store = {}

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None
    def select_file(self):
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True) 
        file_path = filedialog.askopenfilename(title="Select a File")
        root.destroy()
        return file_path if file_path else None
    def add_file(self):
        file_path = self.select_file()
        if file_path:
            file_hash = self.calculate_hash(file_path)
            if file_hash:
                self.hash_store[file_path] = file_hash
                print(f"\033[92mFile added successfully: {os.path.basename(file_path)}\033[0m")
            else:
                print(f"\033[91mFile not found.\033[0m")

    def verify_file(self):
        file_path = self.select_file()
        if file_path:
            if file_path not in self.hash_store:
                print(f"\033[93mFile not tracked. Add it first.\033[0m")
                return
            current_hash = self.calculate_hash(file_path)
            if current_hash == self.hash_store[file_path]:
                print(f"\033[92mFile integrity verified. No changes detected.\033[0m")
            else:
                print(f"\033[91mWarning: File has been modified!\033[0m")

    def run(self):
        while True:
            print("\n1. Add File\n2. Verify File\n3. Exit")
            choice = input("Choose an option: ")
            if choice == "1":
                self.add_file()
            elif choice == "2":
                self.verify_file()
            elif choice == "3":
                print("\033[94mExiting...\033[0m")
                break
            else:
                print("\033[91mInvalid option.\033[0m")

if __name__ == "__main__":
    checker = FileIntegrityChecker()
    checker.run()
