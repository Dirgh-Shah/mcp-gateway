import json
import tempfile
from pathlib import Path

import pytest

from app.auth import AuthError, KeyStore, generate_key, hash_secret


def _store_with(principal="alice", role="reader"):
    plaintext, record = generate_key(principal, role)
    return plaintext, KeyStore([record])


def test_valid_key_resolves_to_the_right_principal():
    plaintext, store = _store_with("alice", "reader")
    principal = store.authenticate(plaintext)
    assert principal.name == "alice"
    assert principal.role == "reader"
    assert principal.key_id == plaintext.split("_")[1]


def test_wrong_secret_is_rejected():
    plaintext, store = _store_with()
    key_id = plaintext.split("_")[1]
    forged = f"mcpg_{key_id}_{'z' * 43}"
    with pytest.raises(AuthError):
        store.authenticate(forged)


def test_unknown_key_id_is_rejected():
    plaintext, store = _store_with()
    secret = plaintext.split("_", 2)[2]
    with pytest.raises(AuthError):
        store.authenticate(f"mcpg_{'0' * 12}_{secret}")


def test_malformed_keys_are_rejected():
    _, store = _store_with()
    for bad in ["", "not-a-key", "mcpg_short_x", "Bearer mcpg_abc_def", "mcpg__"]:
        with pytest.raises(AuthError):
            store.authenticate(bad)


def test_failure_messages_do_not_distinguish_failure_modes():
    plaintext, store = _store_with()
    key_id = plaintext.split("_")[1]
    messages = set()
    for bad in [f"mcpg_{'0' * 12}_{'a' * 43}", f"mcpg_{key_id}_{'a' * 43}", "garbage"]:
        try:
            store.authenticate(bad)
        except AuthError as exc:
            messages.add(str(exc))
    assert messages == {"invalid API key"}


def test_disabled_key_is_rejected():
    plaintext, record = generate_key("alice", "reader")
    store = KeyStore([type(record)(**{**record.__dict__, "disabled": True})])
    with pytest.raises(AuthError):
        store.authenticate(plaintext)


def test_secret_is_never_stored_in_plaintext():
    plaintext, record = generate_key("alice", "reader")
    secret = plaintext.split("_", 2)[2]
    serialized = json.dumps(record.__dict__)
    assert secret not in serialized
    assert record.secret_sha256 == hash_secret(secret)


def test_generated_keys_are_unique():
    keys = {generate_key("alice", "reader")[0] for _ in range(50)}
    assert len(keys) == 50


def test_round_trips_through_a_file():
    plaintext, store = _store_with("bob", "editor")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "keys.json"
        store.save(path)
        reloaded = KeyStore.load(path)
        assert reloaded.authenticate(plaintext).name == "bob"


def test_duplicate_key_ids_are_rejected():
    _, record = generate_key("alice", "reader")
    with pytest.raises(ValueError):
        KeyStore([record, record])
