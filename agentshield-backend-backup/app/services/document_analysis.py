import re
from io import BytesIO
from pypdf import PdfReader
from app.security.policies import ALLOWED_PAYMENT_VENDORS, MAX_PAYMENT_AMOUNT

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024


def extract_document_text(filename: str, content_type: str, data: bytes) -> str:
    if not data:
        raise ValueError("Uploaded file is empty")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("File exceeds the 5 MB limit")
    name = (filename or "").lower()
    if content_type == "application/pdf" or name.endswith(".pdf"):
        try:
            reader = PdfReader(BytesIO(data), strict=False)
            text = "\n".join((page.extract_text() or "") for page in reader.pages[:30])
        except Exception as exc:
            raise ValueError("Could not read this PDF. Try a text-based PDF.") from exc
        if not text.strip():
            raise ValueError("No selectable text found. Scanned-image PDFs need OCR, which is not enabled in this version.")
        return text[:30000]
    if content_type in {"text/plain", "text/markdown", "application/octet-stream"} or name.endswith((".txt", ".md", ".csv")):
        try:
            return data.decode("utf-8-sig")[:30000]
        except UnicodeDecodeError as exc:
            raise ValueError("Text file must be UTF-8 encoded") from exc
    raise ValueError("Only text files and text-based PDFs are supported")


def analyze_invoice(text: str) -> dict:
    """Deterministic demo analyzer; extracted content is data, never executable instructions."""
    lower = text.lower()
    # Semantic-ish phrase families for a demo signal, not a complete prompt-injection detector.
    injection_patterns = [
        r"ignore (all |any )?(previous|prior|above) instructions",
        r"disregard (the )?(system|developer|previous) prompt",
        r"override (the )?(security|approval|payment|guardian) (policy|rules|checks)",
        r"send (all |the )?(files|secrets|credentials|customer data) to",
        r"bypass (approval|security|verification|the guardian)",
        r"do not tell (the )?(user|owner|finance|guardian)",
        r"change the beneficiary|new bank account|urgent wire transfer|pay immediately",
        r"you are now (an admin|the system|a different agent)",
    ]
    signals = [pattern for pattern in injection_patterns if re.search(pattern, lower)]
    vendor_match = re.search(r"(?:vendor|supplier|payee)\s*[:#-]\s*([A-Za-z0-9][A-Za-z0-9 .&_-]{1,70})", text, re.I)
    amount_match = re.search(r"(?:total|amount|invoice amount|payable)\s*[:=-]?\s*(?:INR|Rs\.?|₹)?\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", text, re.I)
    vendor = vendor_match.group(1).strip().rstrip(".,") if vendor_match else None
    amount = float(amount_match.group(1).replace(",", "")) if amount_match else None
    flags = []
    if signals:
        flags.append("Possible prompt-injection or payment-manipulation instructions detected")
    if not vendor:
        flags.append("Vendor could not be reliably extracted")
    elif vendor not in ALLOWED_PAYMENT_VENDORS:
        flags.append("Vendor is not on the trusted-vendor allow-list")
    if amount is None:
        flags.append("Amount could not be reliably extracted")
    elif amount <= 0 or amount > MAX_PAYMENT_AMOUNT:
        flags.append(f"Amount is outside the demo policy limit (0–{MAX_PAYMENT_AMOUNT:.2f})")
    # Approval is always required; suspicious/missing data means block/escalate.
    decision = "BLOCK" if signals or (vendor and vendor not in ALLOWED_PAYMENT_VENDORS) or (amount is not None and (amount <= 0 or amount > MAX_PAYMENT_AMOUNT)) else "REVIEW_REQUIRED"
    return {"vendor": vendor, "amount": amount, "prompt_injection_suspected": bool(signals),
            "injection_signals": signals, "flags": flags, "guardian_decision": decision,
            "payment_execution": "SIMULATED_ONLY", "text_length": len(text)}
