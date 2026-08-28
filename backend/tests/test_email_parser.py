import os
import pytest
from fastapi.testclient import TestClient
from email.message import EmailMessage

# Adjust imports to correctly refer to the app
from app.main import app
from app.services.ingestion.parser import EmailParser

client = TestClient(app)

@pytest.fixture
def sample_eml_bytes():
    msg = EmailMessage()
    msg['Subject'] = 'Test Subject'
    msg['From'] = 'sender@example.com'
    msg['To'] = 'recipient@example.com'
    msg['Date'] = 'Tue, 12 Oct 2021 10:10:10 -0000'
    msg['Message-ID'] = '<12345@example.com>'
    msg['Reply-To'] = 'reply@example.com'
    msg.add_header('Received', 'from mail.example.com by mx.example.com with SMTP id 123; Tue, 12 Oct 2021 10:10:10 -0000')
    msg.set_content('This is a plain text body with a URL: http://example.com/link')
    
    msg.add_alternative(
        '<html><body><p>HTML body with a link <a href="http://example.com/html-link">Click here</a></p></body></html>',
        subtype='html'
    )
    
    msg.add_attachment(b'Fake PDF content', maintype='application', subtype='pdf', filename='invoice.pdf')
    
    return msg.as_bytes()

def test_parser_extracts_all_components(sample_eml_bytes, tmp_path):
    parser = EmailParser(storage_dir=str(tmp_path))
    parsed = parser.parse(sample_eml_bytes)
    
    # Check headers
    assert parsed.headers.subject == "Test Subject"
    assert parsed.headers.from_address == "sender@example.com"
    assert parsed.headers.from_domain == "example.com"
    assert parsed.headers.reply_to == "reply@example.com"
    assert parsed.headers.reply_to_domain == "example.com"
    assert parsed.message_id == "<12345@example.com>"
    
    # Check received hops
    assert len(parsed.headers.received_hops) == 1
    assert parsed.headers.received_hops[0].from_host == "mail.example.com"
    assert parsed.headers.received_hops[0].by_host == "mx.example.com"
    
    # Check body
    assert "This is a plain text body" in parsed.plain_text
    assert "HTML body with a link" in parsed.html
    
    # Check URLs
    assert "http://example.com/link" in parsed.urls
    assert "http://example.com/html-link" in parsed.urls
    
    # Check attachments
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.pdf"
    assert parsed.attachments[0].size_bytes == 16
    assert parsed.attachments[0].mime_type == "application/pdf"
    
    # Check provenance
    assert os.path.exists(parsed.raw_artifact_reference)

def test_api_endpoint(sample_eml_bytes):
    response = client.post(
        "/api/v1/emails/analyze",
        files={"file": ("test.eml", sample_eml_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()
    
    assert data["message_id"] == "<12345@example.com>"
    assert data["headers"]["subject"] == "Test Subject"
    assert data["headers"]["from_domain"] == "example.com"
    assert "http://example.com/link" in data["urls"]
    assert len(data["attachments"]) == 1
    assert data["attachments"][0]["filename"] == "invoice.pdf"

def test_malformed_email():
    # Graceful handling of garbage
    garbage_bytes = b"This is not a valid email format"
    response = client.post(
        "/api/v1/emails/analyze",
        files={"file": ("garbage.eml", garbage_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["headers"]["subject"] is None
    assert data["plain_text"] == "This is not a valid email format"
    assert data["html"] is None
