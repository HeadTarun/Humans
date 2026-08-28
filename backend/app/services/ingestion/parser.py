import email
import email.policy
from email.message import EmailMessage
import hashlib
import os
import re
import uuid
from datetime import datetime
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional

from bs4 import BeautifulSoup

from app.contracts.email import ParsedEmail
from app.contracts.headers import HeaderSet, ReceivedHop
from app.contracts.attachment import AttachmentRef


def extract_domain(address: Optional[str]) -> Optional[str]:
    """Extract domain from an email address string safely."""
    if not address:
        return None
    _, email_addr = parseaddr(address)
    if not email_addr:
        return None
    parts = email_addr.rsplit('@', 1)
    if len(parts) == 2 and parts[1]:
        return parts[1].strip()
    return None

def parse_received_hop(index: int, header_val: str) -> ReceivedHop:
    """Parse a single Received header loosely."""
    header_val = header_val.replace('\r', '').replace('\n', ' ').strip()
    
    from_match = re.search(r'from\s+([^\s]+)', header_val, re.IGNORECASE)
    by_match = re.search(r'by\s+([^\s;]+)', header_val, re.IGNORECASE)
    
    from_host = from_match.group(1) if from_match else None
    by_host = by_match.group(1) if by_match else None
    
    timestamp = None
    parts = header_val.split(';')
    if len(parts) >= 2:
        date_str = parts[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_str)
        except (ValueError, TypeError, IndexError):
            pass

    return ReceivedHop(
        hop_index=index,
        from_host=from_host,
        by_host=by_host,
        raw_line=header_val,
        timestamp=timestamp
    )

class EmailParser:
    def __init__(self, storage_dir: str = "/tmp/emails"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        
        # Save raw artifact
        artifact_filename = f"{sha256}.eml"
        artifact_path = os.path.join(self.storage_dir, artifact_filename)
        if not os.path.exists(artifact_path):
            with open(artifact_path, "wb") as f:
                f.write(raw_bytes)

        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        
        from_header = msg.get("From")
        reply_to_header = msg.get("Reply-To")
        return_path_header = msg.get("Return-Path")
        
        raw_headers = {}
        for k, v in msg.items():
            if k not in raw_headers:
                raw_headers[k] = str(v)
            else:
                raw_headers[k] = f"{raw_headers[k]}, {v}"

        date_header = msg.get("Date")
        date_dt = None
        if date_header:
            try:
                date_dt = parsedate_to_datetime(str(date_header))
            except Exception:
                pass

        received_headers = msg.get_all("Received", [])
        hops = [parse_received_hop(i, str(h)) for i, h in enumerate(received_headers)]

        # Get Authentication-Results as a single concatenated string if multiple
        auth_results_list = msg.get_all("Authentication-Results", [])
        auth_results_raw = " | ".join(str(ar) for ar in auth_results_list) if auth_results_list else None

        header_set = HeaderSet(
            from_address=str(from_header) if from_header else None,
            from_domain=extract_domain(str(from_header)) if from_header else None,
            reply_to=str(reply_to_header) if reply_to_header else None,
            reply_to_domain=extract_domain(str(reply_to_header)) if reply_to_header else None,
            return_path=str(return_path_header) if return_path_header else None,
            return_path_domain=extract_domain(str(return_path_header)) if return_path_header else None,
            message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
            subject=str(msg.get("Subject")) if msg.get("Subject") else None,
            date=date_dt,
            received_hops=hops,
            authentication_results_raw=auth_results_raw,
            raw_headers=raw_headers
        )

        plain_text_parts = []
        html_parts = []
        attachments = []
        urls = set()

        for part in msg.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")
            
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            # Identify if it is an attachment
            filename = part.get_filename()
            if "attachment" in content_disposition or ("inline" in content_disposition and filename):
                filename = filename or f"unnamed_{uuid.uuid4().hex[:8]}"
                part_sha256 = hashlib.sha256(payload).hexdigest()
                attachments.append(AttachmentRef(
                    attachment_id=uuid.uuid4().hex,
                    filename=filename,
                    mime_type=content_type,
                    size_bytes=len(payload),
                    sha256=part_sha256
                ))
            else:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text_content = payload.decode(charset, errors="replace")
                except LookupError:
                    text_content = payload.decode("utf-8", errors="replace")

                if content_type == "text/plain":
                    plain_text_parts.append(text_content)
                    found_urls = re.findall(r'(https?://[^\s<>"]+)', text_content)
                    urls.update(found_urls)
                elif content_type == "text/html":
                    html_parts.append(text_content)
                    soup = BeautifulSoup(text_content, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        urls.add(a['href'])
                    for img in soup.find_all('img', src=True):
                        urls.add(img['src'])

        plain_text = "\n".join(plain_text_parts) if plain_text_parts else None
        html = "\n".join(html_parts) if html_parts else None

        return ParsedEmail(
            message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
            headers=header_set,
            plain_text=plain_text,
            html=html,
            urls=list(urls),
            attachments=attachments,
            raw_artifact_reference=artifact_path,
            sha256=sha256
        )
