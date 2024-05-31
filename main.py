import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from datetime import datetime
import pytz
import re

# Generate keys for users
karina_key = Fernet.generate_key()
ulzhan_key = Fernet.generate_key()

# Store keys and messages in a dictionary
users = {
    "karina": {"password": "Karina@1234", "key": karina_key, "messages": []},
    "ulzhan": {"password": "Ulzhan@1234", "key": ulzhan_key, "messages": []}
}


# Function to encrypt messages
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message


# Function to decrypt messages
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message


# Function to validate password
def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# Define the application class
class SecureMessengerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Messenger")
        self.geometry("600x550")
        self.configure(bg="#e6f7ff")
        self.username = None
        self.create_widgets()

    def create_widgets(self):
        self.login_frame = tk.Frame(self, bg="#e6f7ff")
        self.login_frame.pack(pady=20)

        self.login_label = tk.Label(self.login_frame, text="Enter Username:", bg="#e6f7ff", font=("Helvetica", 12))
        self.login_label.grid(row=0, column=0, pady=5)
        self.username_entry = tk.Entry(self.login_frame, font=("Helvetica", 12))
        self.username_entry.grid(row=0, column=1, pady=5, padx=5)

        self.password_label = tk.Label(self.login_frame, text="Enter Password:", bg="#e6f7ff", font=("Helvetica", 12))
        self.password_label.grid(row=1, column=0, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Helvetica", 12))
        self.password_entry.grid(row=1, column=1, pady=5, padx=5)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login, bg="#4CAF50", fg="white",
                                      font=("Helvetica", 12), relief="flat")
        self.login_button.grid(row=2, columnspan=2, pady=10)

        self.message_label = tk.Label(self, text="Message:", bg="#e6f7ff", font=("Helvetica", 12))
        self.message_text = tk.Text(self, height=5, font=("Helvetica", 12))
        self.recipient_label = tk.Label(self, text="Recipient:", bg="#e6f7ff", font=("Helvetica", 12))
        self.recipient_entry = tk.Entry(self, font=("Helvetica", 12))
        self.send_button = tk.Button(self, text="Send Message", command=self.send_message, bg="#4CAF50", fg="white",
                                     font=("Helvetica", 12), relief="flat")
        self.logout_button = tk.Button(self, text="Logout", command=self.logout, bg="#f44336", fg="white",
                                       font=("Helvetica", 12), relief="flat")
        self.messages_frame = tk.Frame(self, bg="#e6f7ff")

        self.footer_label = tk.Label(self, text="Hello to the messenger!", bg="#e6f7ff", font=("Helvetica", 10),
                                     fg="gray")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in users and users[username]['password'] == password:
            self.username = username
            self.login_frame.pack_forget()
            self.show_messenger()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_messenger(self):
        self.message_label.pack(pady=10)
        self.message_text.pack(pady=10, padx=10)
        self.recipient_label.pack(pady=10)
        self.recipient_entry.pack(pady=10, padx=10)
        self.send_button.pack(pady=10)
        self.logout_button.pack(pady=10)
        self.messages_frame.pack(pady=10)
        self.display_messages()
        self.footer_label.pack(side="bottom", pady=10)

    def display_messages(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        for idx, msg in enumerate(users[self.username]['messages']):
            msg_text = f"From: {msg['sender']}\nMessage: {msg['message']}\nTimestamp: {msg['timestamp']}"
            msg_label = tk.Label(self.messages_frame, text=msg_text, relief="solid", pady=5, bg="#fff",
                                 font=("Helvetica", 10))
            msg_label.pack(fill="x", padx=5, pady=5)
            decrypt_button = tk.Button(self.messages_frame, text="Decrypt",
                                       command=lambda idx=idx: self.decrypt_message(idx), bg="#008CBA", fg="white",
                                       font=("Helvetica", 10), relief="flat")
            decrypt_button.pack(pady=5)

    def send_message(self):
        recipient = self.recipient_entry.get()
        message = self.message_text.get("1.0", tk.END).strip()
        if recipient in users and message:
            key = users[recipient]['key']  # Encrypt with the recipient's key
            encrypted_message = encrypt_message(message, key)
            timestamp = datetime.now(pytz.timezone('Asia/Qyzylorda')).strftime('%Y-%m-%d %H:%M:%S %ZGMT')
            users[recipient]['messages'].append(
                {"sender": self.username, "message": encrypted_message, "timestamp": timestamp})
            self.message_text.delete("1.0", tk.END)
            messagebox.showinfo("Success", "Message sent successfully")
        else:
            messagebox.showerror("Error", "Invalid recipient or message")

    def decrypt_message(self, index):
        message = users[self.username]['messages'][index]
        key = users[self.username]['key']
        try:
            decrypted_message = decrypt_message(message['message'], key)
            users[self.username]['messages'][index]['message'] = decrypted_message
            self.display_messages()
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt message: {str(e)}")

    def logout(self):
        self.username = None
        self.message_label.pack_forget()
        self.message_text.pack_forget()
        self.recipient_label.pack_forget()
        self.recipient_entry.pack_forget()
        self.send_button.pack_forget()
        self.logout_button.pack_forget()
        self.messages_frame.pack_forget()
        self.footer_label.pack_forget()
        self.create_widgets()


if __name__ == "__main__":
    app = SecureMessengerApp()
    app.mainloop()
