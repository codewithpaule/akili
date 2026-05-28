import re


def redact_text(text: str) -> str:
    if not text:
        return text
    # redact emails
    text = re.sub(r"[\w\.-]+@[\w\.-]+", "[redacted_email]", text)
    # redact simple credit-card-like numbers
    text = re.sub(r"\b\d{12,19}\b", "[redacted_number]", text)
    return text
