import traceback
import hashlib
import getpass
import random
import string
import tkinter as tk
from tkinter import messagebox

class PasswordAuthentication:
    def __init__(self):
        self.users = {}

    def generate_captcha(self): 
        captcha_challenge = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return captcha_challenge

    def authenticate_captcha(self, user_input, captcha_challenge):
        return user_input.upper() == captcha_challenge

    def generate_challenge(self): 
        num1 = 5
        num2 = 9
        solution = num1 + num2
        return num1, num2, solution

    def verify_solution(self, entry, solution):
        user_answer = entry.get()
        try:
            user_answer = int(user_answer)
            if user_answer == solution:
                messagebox.showinfo("Success", "Verification successful. You are human!") 
            else:
                messagebox.showerror("Error", "Verification failed. Please try again.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid numeric answer.")

    def register_user(self, username, password):
        hashed_password = self._hash_password(password)
        self.users[username] = hashed_password
        print(f"User {username} registered successfully.")

    def authenticate_user(self, username, password):
        if username in self.users:
            if self._verify_password(password, self.users[username]):
                print(f"User {username} authenticated successfully.")
                return True
            else:
                print("Incorrect password.")
        else:
            print("User not found. Please register.")

    def _hash_password(self, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password

    def _verify_password(self, input_password, stored_password):
        return self._hash_password(input_password) == stored_password

if __name__ == "__main__":
    password_auth = PasswordAuthentication()
    while True:
        print("Enter 1 to sign up")
        print("Enter 2 to login")
        print("Enter 3 to exit")
        n = input()

        if(n == '1'):
            username = input("Enter the username for the new signup: ")
            password_auth.register_user(username, getpass.getpass(f"Enter password for {username}: "))

        elif (n == '2'):
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            captcha = password_auth.generate_captcha()
            print(f"Enter the Captcha : {captcha}")
            user_response = input() 
            if password_auth.authenticate_captcha(user_response, captcha):
                print("CAPTCHA authentication successful.")

                root = tk.Tk()
                root.title("Human Verification")
                root.geometry("400x200")
                num1, num2, solution = password_auth.generate_challenge()
                label = tk.Label(root, text="Verify that you are human:")
                label.pack(pady=10)
                question_label = tk.Label(root, text=f"What is {num1} + {num2}?")
                question_label.pack()
                entry_label = tk.Label(root, text="Your answer:")
                entry_label.pack()
                entry = tk.Entry(root)
                entry.pack(pady=10)
                verify_button = tk.Button(root, text="Verify", command=lambda: password_auth.verify_solution(entry, solution))
                verify_button.pack()
                root.mainloop()

                password_auth.authenticate_user(username, password)  
            else:
                print("CAPTCHA authentication failed.")
            
        elif (n == '3'):
            exit()


