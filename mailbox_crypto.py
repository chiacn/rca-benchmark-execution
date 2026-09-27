"""Session-bound encrypted envelopes; only public keys/envelopes enter GitHub."""
import base64
import json
import os
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EnvelopeError(ValueError):
    pass


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _binding(session, seq, direction):
    if str(uuid.UUID(session)) != session:
        raise EnvelopeError("invalid_session")
    if type(seq) is not int or seq < 1 or direction not in ("request", "response"):
        raise EnvelopeError("invalid_envelope_binding")
    return _json({"session": session, "seq": seq, "direction": direction,
                  "protocol": "rca-mailbox-aesgcm/1"})


def generate_keypair():
    private = X25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return private, base64.b64encode(raw).decode("ascii")


def derive_key(private, peer_b64, session):
    try:
        if str(uuid.UUID(session)) != session:
            raise ValueError()
        raw = base64.b64decode(peer_b64, validate=True)
        if len(raw) != 32:
            raise ValueError()
        shared = private.exchange(X25519PublicKey.from_public_bytes(raw))
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=None,
                    info=b"rca-mailbox-key/1:" + session.encode("ascii")).derive(shared)
    except Exception:
        raise EnvelopeError("invalid_peer_key_or_session") from None


def seal(key, session, seq, direction, payload):
    aad = _binding(session, seq, direction)
    raw = _json(payload)
    if len(raw) > 65536:
        raise EnvelopeError("payload_too_large")
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, raw, aad)
    return {"session": session, "seq": seq,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted).decode("ascii")}


def open_envelope(key, session, seq, direction, envelope):
    try:
        aad = _binding(session, seq, direction)
        if type(envelope) is not dict or set(envelope) != {"session", "seq", "nonce", "ciphertext"}:
            raise ValueError()
        if envelope["session"] != session or type(envelope["seq"]) is not int or envelope["seq"] != seq:
            raise ValueError()
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        encrypted = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(nonce) != 12 or not 16 <= len(encrypted) <= 65552:
            raise ValueError()
        payload = AESGCM(key).decrypt(nonce, encrypted, aad)
        return json.loads(payload)
    except Exception:
        raise EnvelopeError("envelope_authentication_failed") from None
