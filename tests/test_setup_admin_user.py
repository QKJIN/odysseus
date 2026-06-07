import importlib.util
import json
from pathlib import Path

import bcrypt


def _load_setup_module():
    spec = importlib.util.spec_from_file_location("odysseus_setup_under_test", Path("setup.py"))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_create_default_admin_normalizes_env_username(tmp_path, monkeypatch):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ODYSSEUS_ADMIN_USER", " AdminUser ")
    monkeypatch.setenv("ODYSSEUS_ADMIN_PASSWORD", "temporary-password")

    assert setup_module.create_default_admin() == "created"

    auth_path = tmp_path / "auth.json"
    data = json.loads(auth_path.read_text(encoding="utf-8"))
    assert "adminuser" in data["users"]
    assert "AdminUser" not in data["users"]


def test_create_default_admin_can_reset_existing_admin_password(tmp_path, monkeypatch):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "DATA_DIR", str(tmp_path))

    old_hash = bcrypt.hashpw(b"old-password", bcrypt.gensalt()).decode()
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(
        json.dumps({
            "users": {
                "admin": {
                    "password_hash": old_hash,
                    "is_admin": True,
                    "totp_enabled": True,
                    "totp_secret": "secret",
                    "totp_backup_codes": ["code"],
                }
            }
        }),
        encoding="utf-8",
    )
    (tmp_path / "sessions.json").write_text(json.dumps({"token": {"username": "admin"}}), encoding="utf-8")
    monkeypatch.setenv("ODYSSEUS_RESET_ADMIN_PASSWORD", "true")
    monkeypatch.setenv("ODYSSEUS_ADMIN_PASSWORD", "new-password")

    assert setup_module.create_default_admin() == "reset"

    data = json.loads(auth_path.read_text(encoding="utf-8"))
    admin = data["users"]["admin"]
    assert bcrypt.checkpw(b"new-password", admin["password_hash"].encode())
    assert admin["is_admin"] is True
    assert admin["totp_enabled"] is False
    assert "totp_secret" not in admin
    assert json.loads((tmp_path / "sessions.json").read_text(encoding="utf-8")) == {}


def test_create_default_admin_does_not_reset_without_explicit_flag(tmp_path, monkeypatch):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "DATA_DIR", str(tmp_path))

    old_hash = bcrypt.hashpw(b"old-password", bcrypt.gensalt()).decode()
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(
        json.dumps({"users": {"admin": {"password_hash": old_hash, "is_admin": True}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ODYSSEUS_ADMIN_PASSWORD", "new-password")

    assert setup_module.create_default_admin() == "exists"

    data = json.loads(auth_path.read_text(encoding="utf-8"))
    assert bcrypt.checkpw(b"old-password", data["users"]["admin"]["password_hash"].encode())
