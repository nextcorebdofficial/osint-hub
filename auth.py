"""Passwords, sessions and input checks for email accounts. Standard library only."""
import base64
import hashlib
import hmac
import re
import secrets
import time

EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
MIN_PASSWORD, MAX_PASSWORD = 12, 128
COMMON = {"password1234", "123456789012", "qwertyuiop12", "administrator", "welcome12345",
          "iloveyou1234", "letmein12345", "passw0rd1234", "1234567890ab"}

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
_SESSION_DAYS = 7


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


# Checked against when the email is unknown, so a miss costs the same time as a hit.
DUMMY_HASH = hash_password(secrets.token_hex(8))


# ---------------------------------------------------------------- input checks

def clean_email(value: str) -> str:
    e = (value or "").strip().lower()
    if len(e) > 254 or not EMAIL_RE.fullmatch(e):
        raise ValueError("Enter a valid email address.")
    return e


def check_password(password: str, email: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Use at least {MIN_PASSWORD} characters.")
    if len(password) > MAX_PASSWORD:
        raise ValueError(f"Use at most {MAX_PASSWORD} characters.")
    low = password.lower()
    if low in COMMON or len(set(password)) < 5:
        raise ValueError("That password is too easy to guess.")
    if email and (low == email or low == email.split("@")[0]):
        raise ValueError("The password must not be your email address.")


# ---------------------------------------------------------------- sessions (signed, stateless)

def fingerprint(user: dict) -> str:
    """Changes when the password changes, which signs the user out everywhere."""
    return hashlib.sha256(user["pw"].encode()).hexdigest()[:16]


def _sig(secret: str, uid: int, exp: int, fp: str) -> str:
    return hmac.new(secret.encode(), f"{uid}.{exp}.{fp}".encode(), hashlib.sha256).hexdigest()


def make_session(secret: str, user: dict) -> str:
    exp = int(time.time()) + _SESSION_DAYS * 86400
    return f"{user['id']}.{exp}.{_sig(secret, user['id'], exp, fingerprint(user))}"


def session_uid(token: str) -> int | None:
    """The user id a token claims, before it has been verified. None if malformed or expired."""
    try:
        uid, exp, _ = token.split(".")
        return int(uid) if int(exp) > time.time() else None
    except (ValueError, AttributeError):
        return None


def session_valid(secret: str, token: str, user: dict) -> bool:
    try:
        uid, exp, sig = token.split(".")
        return (int(uid) == user["id"] and int(exp) > time.time()
                and hmac.compare_digest(sig, _sig(secret, user["id"], int(exp), fingerprint(user))))
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------- email links (verify, reset)
# Signed and stateless. A reset token is bound to the current password hash, so it works once:
# after the password changes it no longer matches.

LINK_HOURS = {"verify": 48, "reset": 1}


def _link_binding(kind: str, user: dict) -> str:
    return user["email"] if kind == "verify" else fingerprint(user)


def make_link_token(secret: str, kind: str, user: dict) -> str:
    exp = int(time.time()) + LINK_HOURS[kind] * 3600
    sig = hmac.new(secret.encode(), f"{kind}.{user['id']}.{exp}.{_link_binding(kind, user)}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{user['id']}.{exp}.{sig}"


def link_token_uid(token: str) -> int | None:
    try:
        uid, exp, _ = token.split(".")
        return int(uid) if int(exp) > time.time() else None
    except (ValueError, AttributeError):
        return None


def link_token_valid(secret: str, kind: str, token: str, user: dict) -> bool:
    try:
        uid, exp, sig = token.split(".")
        want = hmac.new(secret.encode(), f"{kind}.{uid}.{exp}.{_link_binding(kind, user)}".encode(),
                        hashlib.sha256).hexdigest()
        return int(uid) == user["id"] and int(exp) > time.time() and hmac.compare_digest(sig, want)
    except (ValueError, AttributeError):
        return False
