import requests
import json
import time
from cryptography.fernet import Fernet
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import base64
import os

class RobloxModeration:
    def __init__(self):
        self.cookie = None
        self.group_id = None
        self.fernet = None
        self.license_key = None
        self.license_expiry = None
        self.stats = {
            "deleted_posts": 0,
            "deleted_spam": 0,
            "deleted_scam": 0,
            "deleted_ads": 0
        }
        self.spam_users = {}
        self.real_time_moderation = False

    def set_encryption_key(self, key):
        self.fernet = Fernet(key)

    def encrypt_data(self, data):
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        return self.fernet.decrypt(encrypted_data.encode()).decode()

    def set_cookie(self, cookie):
        self.cookie = self.encrypt_data(cookie)

    def set_group_id(self, group_id):
        self.group_id = self.encrypt_data(str(group_id))

    def save_settings(self):
        settings = {
            "cookie": self.cookie,
            "group_id": self.group_id,
            "license_key": self.license_key,
            "license_expiry": self.license_expiry.isoformat() if self.license_expiry else None
        }
        with open("settings.json", "w") as f:
            json.dump(settings, f)

    def load_settings(self):
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
            self.cookie = settings.get("cookie")
            self.group_id = settings.get("group_id")
            self.license_key = settings.get("license_key")
            self.license_expiry = datetime.datetime.fromisoformat(settings["license_expiry"]) if settings.get("license_expiry") else None
        except FileNotFoundError:
            pass

    def check_license(self):
        if not self.license_key or not self.license_expiry:
            return False
        return datetime.datetime.now() < self.license_expiry

    def activate_license(self, license_key):
        if len(license_key) == 16:
            self.license_key = license_key
            self.license_expiry = datetime.datetime.now() + datetime.timedelta(days=30)
            self.save_settings()
            return True
        return False

    def get_group_wall(self):
        url = f"https://groups.roblox.com/v2/groups/{self.decrypt_data(self.group_id)}/wall/posts?limit=100&sortOrder=Desc"
        headers = {"Cookie": f".ROBLOSECURITY={self.decrypt_data(self.cookie)}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an error for bad responses
            return response.json().get("data", [])
        except requests.RequestException as e:
            print(f"Error fetching group wall: {e}")
            return []

    def delete_post(self, post_id):
        url = f"https://groups.roblox.com/v1/groups/{self.decrypt_data(self.group_id)}/wall/posts/{post_id}"
        headers = {"Cookie": f".ROBLOSECURITY={self.decrypt_data(self.cookie)}"}
        try:
            response = requests.delete(url, headers=headers)
            return response.status_code == 200
        except requests.RequestException as e:
            print(f"Error deleting post: {e}")
            return False

    def moderate_posts(self):
        posts = self.get_group_wall()
        for post in posts:
            if self.is_spam(post):
                if self.delete_post(post["id"]):
                    self.stats["deleted_spam"] += 1
            elif self.is_scam(post):
                if self.delete_post(post["id"]):
                    self.stats["deleted_scam"] += 1
            elif self.is_ad(post):
                if self.delete_post(post["id"]):
                    self.stats["deleted_ads"] += 1

    def is_spam(self, post):
        user_id = post["poster"]["userId"]
        current_time = time.time()
        if user_id in self.spam_users:
            if current_time - self.spam_users[user_id]["last_post"] < 45:
                self.spam_users[user_id]["count"] += 1
                if self.spam_users[user_id]["count"] >= 4:
                    return True
            else:
                self.spam_users[user_id]["count"] = 1
        else:
            self.spam_users[user_id] = {"count": 1, "last_post": current_time}
        self.spam_users[user_id]["last_post"] = current_time
        return False

    def is_scam(self, post):
        content = post["body"].lower()
        return content.startswith("https://www.roblox.com/groups/") and str(self.decrypt_data(self.group_id)) not in content

    def is_ad(self, post):
        return post["body"].lower().startswith("https://www.roblox.com/games/")

    def start_real_time_moderation(self):
        self.real_time_moderation = True
        while self.real_time_moderation:
            self.moderate_posts()
            time.sleep(60)  # Check every minute

    def stop_real_time_moderation(self):
        self.real_time_moderation = False

    def auto_detect(self, callback):
        total_posts = len(self.get_group_wall())
        for i, post in enumerate(self.get_group_wall()):
            if self.is_spam(post) or self.is_scam(post) or self.is_ad(post):
                if self.delete_post(post["id"]):
                    self.stats["deleted_posts"] += 1
            progress = (i + 1) / total_posts if total_posts > 0 else 1
            eta = (total_posts - i - 1) * 0.5  # Assuming 0.5 seconds per post
            callback(progress, eta, f"Checking post {i + 1} of {total_posts}")
            time.sleep(0.5)  # Simulating some processing time

class RoGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("RoGrouppy")
        self.root.geometry("850x600")
        self.root.configure(bg="#f0f0f0")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('TLabel', padding=5)

        self.entries = {}
        self.moderation = RobloxModeration()
        
        # Generate or load encryption key
        self.load_or_generate_key()

        self.create_ui()
        self.real_time_var = tk.StringVar(value="OFF")  # Added for real-time moderation toggle

    def load_or_generate_key(self):
        key_file = "encryption_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            key = base64.urlsafe_b64encode(os.urandom(32))
            with open(key_file, "wb") as f:
                f.write(key)
        self.moderation.set_encryption_key(key)

    def create_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.create_stats_frame(main_frame)
        self.create_logs_frame(main_frame)

    def create_stats_frame(self, main_frame):
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.bestselling_var = tk.StringVar()
        bestselling_options = [("1 Day", "1Day"), ("3 Days", "3Days"), ("7 Days", "7Days"), ("30 Days", "30Days")]
        self.bestselling_dropdown = ttk.Combobox(stats_frame, textvariable=self.bestselling_var, values=[opt[0] for opt in bestselling_options], state="readonly")
        self.bestselling_dropdown.pack(fill=tk.X, pady=(0, 5))
        self.bestselling_dropdown.set(bestselling_options[0][0])

        self.stat_labels = {}
        for stat in ["deleted_posts", "deleted_spam", "deleted_scam", "deleted_ads"]:
            label = ttk.Label(stats_frame, text=f"{stat.replace('_', ' ').title()}: 0")
            label.pack(anchor=tk.W, pady=(5, 0))
            self.stat_labels[stat] = label

    def create_logs_frame(self, main_frame):
        logs_frame = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        logs_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.logs_text = tk.Text(logs_frame, wrap=tk.WORD, height=20)
        self.logs_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        settings_button = ttk.Button(logs_frame, text="Settings", command=self.open_settings)
        settings_button.pack(fill=tk.X, pady=(5, 5))

        license_button = ttk.Button(logs_frame, text="License", command=self.open_license)
        license_button.pack(fill=tk.X, pady=(5, 5))

        check_updates_button = ttk.Button(logs_frame, text="Check Updates", command=self.check_updates)
        check_updates_button.pack(fill=tk.X, pady=(5, 5))

        clear_logs_button = ttk.Button(logs_frame, text="Clear Logs", command=self.clear_logs)
        clear_logs_button.pack(fill=tk.X, pady=(5, 5))

    def start_auto_detect(self):
        thread = threading.Thread(target=self.auto_detect_thread)
        thread.start()

    def auto_detect_thread(self):
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Auto-detect Progress")
        progress_bar = ttk.Progressbar(progress_window, length=300, mode='determinate')
        progress_bar.pack(pady=10)
        status_label = ttk.Label(progress_window, text="")
        status_label.pack(pady=5)
        eta_label = ttk.Label(progress_window, text="")
        eta_label.pack(pady=5)

        def update_progress(progress, eta, status):
            progress_bar['value'] = progress * 100
            status_label['text'] = status
            eta_label['text'] = f"ETA: {eta:.2f} seconds"
            if progress >= 1:
                progress_window.destroy()

        self.moderation.auto_detect(update_progress)

    def toggle_real_time_moderation(self):
        if self.real_time_var.get() == "OFF":
            self.real_time_var.set("ON")
            thread = threading.Thread(target=self.moderation.start_real_time_moderation)
            thread.start()
        else:
            self.real_time_var.set("OFF")
            self.moderation.stop_real_time_moderation()

    def open_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")

        ttk.Label(settings_window, text="Moderator Account Cookie:").pack(pady=5)
        cookie_entry = ttk.Entry(settings_window, show="*")
        cookie_entry.pack(pady=5)

        ttk.Label(settings_window, text="Group ID:").pack(pady=5)
        group_id_entry = ttk.Entry(settings_window)
        group_id_entry.pack(pady=5)

        def save_settings():
            self.moderation.set_cookie(cookie_entry.get())
            self.moderation.set_group_id(group_id_entry.get())
            self.moderation.save_settings()
            settings_window.destroy()

        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=10)

    def open_license(self):
        if self.moderation.check_license():
            messagebox.showinfo("License", "Your license is active and valid.")
        else:
            license_window = tk.Toplevel(self.root)
            license_window.title("Enter License Key")

            ttk.Label(license_window, text="Enter your 16-digit license key:").pack(pady=5)
            license_entry = ttk.Entry(license_window)
            license_entry.pack(pady=5)

            def activate_license():
                if self.moderation.activate_license(license_entry.get()):
                    messagebox.showinfo("License Activated", "Your license has been activated successfully.")
                    license_window.destroy()
                else:
                    messagebox.showerror("Invalid License", "Please enter a valid 16-digit license key.")

            ttk.Button(license_window, text="Activate", command=activate_license).pack(pady=10)

    def check_updates(self):
        # Placeholder for update checking functionality
        messagebox.showinfo("Updates", "No updates available at this time.")

    def clear_logs(self):
        self.logs_text.delete(1.0, tk.END)

    def update_stats(self):
        for stat, value in self.moderation.stats.items():
            if stat in self.stat_labels:
                self.stat_labels[stat].config(text=f"{stat.replace('_', ' ').title()}: {value}")
        self.root.after(1000, self.update_stats)  # Update every second

def main():
    root = tk.Tk()
    app = RoGuard(root)
    
    # Load settings
    app.moderation.load_settings()
    
    # Check license
    if not app.moderation.check_license():
        app.open_license()
    
    # Start updating stats
    app.update_stats()
    
    root.mainloop()

if __name__ == "__main__":
    main()
