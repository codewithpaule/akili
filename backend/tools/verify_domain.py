import uuid

import dns.resolver


def generate_token() -> str:
    return f"akili-verify={uuid.uuid4()}"


def check_txt_record(domain: str, expected_token: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if expected_token in txt or txt == expected_token:
                return True
    except Exception:
        pass
    return False
