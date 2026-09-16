import os
import imaplib
from dotenv import load_dotenv

def discover_folders():
    print("[*] Loading environment variables...")
    load_dotenv()

    server = os.getenv("IMAP_SERVER")
    port = int(os.getenv("IMAP_PORT", 993))
    user = os.getenv("IMAP_USERNAME")
    password = os.getenv("IMAP_PASSWORD")

    if not all([server, user, password]):
        print("[!] ERROR: Missing IMAP credentials in .env file.")
        print("[!] Please configure IMAP_SERVER, IMAP_USERNAME, and IMAP_PASSWORD before running this tool.")
        return

    try:
        print(f"[*] Connecting to {server}:{port} as {user}...")
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        print("[+] Logged in successfully!\n")

        status, folders = mail.list()
        if status == "OK":
            print("=========================================================")
            print(" EXACT IMAP FOLDER NAMES FOR YOUR .ENV FILE")
            print("=========================================================")
            print("Find the folder you want to monitor (e.g., Spam or Junk).")
            print("Copy the extracted name and add it to IMAP_FOLDERS in your .env\n")
            
            for folder in folders:
                folder_str = folder.decode('utf-8', errors='ignore')
                print(f"Raw IMAP Data: {folder_str}")
                
                # Extract the actual folder name (usually the last quoted string)
                try:
                    # Splits by the hierarchy delimiter (usually "/")
                    clean_name = folder_str.split(' "/" ')[-1].strip('"')
                    print(f"-> Use this in .env: {clean_name}\n")
                except Exception:
                    print("") 
        
        mail.logout()
    except imaplib.IMAP4.error as e:
        print(f"[!] Authentication failed: {e}")
        print("[!] Did you use an App Password? Are IMAP settings enabled on your account?")
    except Exception as e:
        print(f"[!] Connection Error: {e}")

if __name__ == "__main__":
    discover_folders()
