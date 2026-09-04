import os
import json
import base64
import secrets
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
USER_KEYS_PATH = os.path.join(KEYS_DIR, "user_keys.json")


def _load_user_keys() -> Dict[str, Any]:
    if not os.path.exists(USER_KEYS_PATH):
        return {}
    with open(USER_KEYS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_user_keys(keys: Dict[str, Any]):
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(USER_KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)


def generate_challenge() -> str:
    return secrets.token_hex(32)


def verify_ed25519_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def generate_demo_user_keypair(user_id: str):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    keys = _load_user_keys()
    keys[user_id] = {
        "public_key_pem": pem_public,
        "private_key_pem": pem_private,
    }
    _save_user_keys(keys)
    return keys[user_id]


def sign_challenge(user_id: str, challenge: str) -> str:
    keys = _load_user_keys()
    if user_id not in keys:
        raise ValueError(f"No keys found for user {user_id}")
    private_pem = keys[user_id]["private_key_pem"].encode("utf-8")
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(challenge.encode("utf-8"))
    return base64.b64encode(signature).decode("utf-8")


def compute_identity_trust(
    user_id: str,
    device_known: bool = False,
    mfa_used: bool = False,
    ip_reputation_good: bool = True,
    challenge: Optional[str] = None,
    signature_b64: Optional[str] = None,
    use_ed25519: bool = False,
) -> Dict[str, Any]:
    """
    Compute identity trust.
    
    If use_ed25519=True:
      - Expects challenge + signature_b64.
      - Verifies signature using stored public key for user_id.
      - identity_verified depends on signature validity.
    
    Else:
      - Uses rule-based trust (device, MFA, IP).
    """
    user_keys = _load_user_keys()

    if use_ed25519:
        if user_id not in user_keys:
            identity_verified = False
            identity_trust = 0.2
        elif challenge is None or signature_b64 is None:
            identity_verified = False
            identity_trust = 0.2
        else:
            public_key_pem = user_keys[user_id]["public_key_pem"]
            sig_valid = verify_ed25519_signature(public_key_pem, challenge, signature_b64)
            identity_verified = sig_valid
            identity_trust = 0.9 if sig_valid else 0.3
    else:
        identity_verified = device_known and mfa_used
        if device_known and mfa_used and ip_reputation_good:
            identity_trust = 0.95
        elif device_known and mfa_used:
            identity_trust = 0.85
        elif device_known:
            identity_trust = 0.6
        else:
            identity_trust = 0.35

    return {
        "identity_verified": identity_verified,
        "device_known": device_known,
        "mfa_used": mfa_used,
        "ip_reputation_good": ip_reputation_good,
        "identity_trust": identity_trust,
        "use_ed25519": use_ed25519,
    }
