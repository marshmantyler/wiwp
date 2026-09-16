import os
import imaplib
import email
import asyncio
from email.header import decode_header
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from sanitizer import extract_urls, defang_url, hash_attachment

class IMAPEngine:
    def __init__(self):
        self.server = os.getenv("IMAP_SERVER")
        self.port = int(os.getenv("IMAP_PORT", 993))
        self.user = os.getenv("IMAP_USERNAME")
        self.password = os.getenv("IMAP_PASSWORD")
        self.alert_email = os.getenv("ALERT_EMAIL_ADDRESS", "").lower()
        
        # Parse the comma-separated list of folders, defaulting to INBOX
        folders_env = os.getenv("IMAP_FOLDERS", "INBOX")
        self.folders = [f.strip() for f in folders_env.split(",") if f.strip()]

    def _decode_mime_words(self, s: str) -> str:
        """Decodes MIME encoded headers safely."""
        if not s:
            return ""
        decoded_words = decode_header(s)
        result = []
        for word, charset in decoded_words:
            if isinstance(word, bytes):
                try:
                    result.append(word.decode(charset or 'utf-8', errors='ignore'))
                except LookupError:
                    result.append(word.decode('utf-8', errors='ignore'))
            else:
                result.append(word)
        return "".join(result)

    def _sync_fetch_unseen(self) -> List[Dict[str, Any]]:
        """
        Synchronous IMAP fetching logic. 
        Cybersec Rationale: This is blocking I/O. It MUST be wrapped in asyncio.to_thread 
        so it doesn't freeze the Discord event loop in Phase 3.
        """
        results = []
        try:
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            mail.login(self.user, self.password)

            # Iterate through all configured folders dynamically
            for folder in self.folders:
                # Attempt to select the folder. Some providers use different names (e.g., "Junk" vs "Spam")
                status, _ = mail.select(folder)
                if status != "OK":
                    print(f"[!] Warning: Could not select IMAP folder '{folder}'. It may not exist on this provider. Skipping.")
                    continue

                status, messages = mail.search(None, "UNSEEN")
                if status != "OK" or not messages[0]:
                    continue # No unread messages in this folder, move to the next

                for num in messages[0].split():
                    status, msg_data = mail.fetch(num, "(RFC822)")
                    if status != "OK":
                        continue

                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            sender = self._decode_mime_words(msg.get("From", "Unknown"))
                            
                            # Loop Prevention: Drop emails from internal alerting systems
                            if self.alert_email and self.alert_email in sender.lower():
                                # Mark as read and skip
                                mail.store(num, '+FLAGS', '\\Seen')
                                continue

                            subject = self._decode_mime_words(msg.get("Subject", "No Subject"))
                            message_id = msg.get("Message-ID", f"generated-{num.decode()}")
                            
                            body_text = ""
                            attachment_hashes = []

                            # Walk through email parts
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get("Content-Disposition"))

                                    if "attachment" in content_disposition:
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            attachment_hashes.append(hash_attachment(payload))
                                    elif content_type == "text/plain":
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            body_text += payload.decode(errors="ignore") + "\n"
                                    elif content_type == "text/html":
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            html = payload.decode(errors="ignore")
                                            # Sanitize HTML to plain text
                                            soup = BeautifulSoup(html, "html.parser")
                                            body_text += soup.get_text(separator=" ", strip=True) + "\n"
                            else:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    body_text = payload.decode(errors="ignore")

                            raw_urls = extract_urls(body_text)
                            
                            results.append({
                                "message_id": message_id,
                                "sender": sender,
                                "subject": subject,
                                "body_preview": body_text[:500], # Keep a preview for LLM context
                                "raw_urls": raw_urls,
                                "defanged_urls": [defang_url(u) for u in raw_urls],
                                "attachment_hashes": attachment_hashes
                            })
                            
                            # Mark as read so we don't process it again
                            mail.store(num, '+FLAGS', '\\Seen')

            mail.logout()
        except Exception as e:
            print(f"[!] IMAP Error: {e}")
            
        return results

    async def fetch_unseen(self) -> List[Dict[str, Any]]:
        """Async wrapper for the blocking IMAP fetch."""
        return await asyncio.to_thread(self._sync_fetch_unseen)
