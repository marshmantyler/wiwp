import re
import hashlib
from typing import List

# Regex to find URLs in text. Kept simple to catch standard HTTP/HTTPS links.
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

def extract_urls(text: str) -> List[str]:
    """Extracts raw URLs from a given text block."""
    if not text:
        return []
    return list(set(URL_REGEX.findall(text)))

def defang_url(url: str) -> str:
    """
    Defangs a URL to prevent accidental clicks in the SOC dashboard/Discord.
    Example: https://malicious.com -> hxxps[://]malicious[.]com
    """
    defanged = url.replace("http", "hxxp")
    defanged = defanged.replace("://", "[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged

def hash_attachment(file_bytes: bytes) -> str:
    """
    Calculates SHA-256 hash of an attachment strictly in-memory.
    Cybersec Rationale: We NEVER write malicious payloads to disk to prevent 
    accidental execution or triggering local endpoint AV/EDR.
    """
    return hashlib.sha256(file_bytes).hexdigest()
