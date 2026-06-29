"""Routing smoke tests — no agent/IdP needed.

These patch the :mod:`hermes_mcp_login.hermes` bridge so the FastAPI wiring can
be exercised without `hermes-agent`, the MCP SDK, or a live IdP installed.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from hermes_mcp_login import hermes
from hermes_mcp_login.app import create_app
from hermes_mcp_login.config import Settings

SETTINGS = Settings(public_base="https://agent.example.test", authorize_timeout=2.0)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(hermes, "oauth_servers", lambda: {"imcontact": {"auth": "oauth"}})
    monkeypatch.setattr(
        hermes, "get_server_cfg",
        lambda name: {"auth": "oauth"} if name == "imcontact" else _raise_key(name),
    )
    monkeypatch.setattr(hermes, "token_present", lambda name: False)
    hermes.SESSIONS.clear()
    return TestClient(create_app(SETTINGS), follow_redirects=False)


def _raise_key(name):
    raise KeyError(name)


def test_index_lists_servers(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "imcontact" in resp.text


def test_status_known_server(client):
    resp = client.get("/mcp/imcontact/status")
    assert resp.status_code == 200
    assert resp.json() == {"name": "imcontact", "token_present": False}


def test_status_unknown_server(client):
    assert client.get("/mcp/nope/status").status_code == 404


def test_login_unknown_server(client):
    assert client.get("/mcp/nope/login").status_code == 404


def test_login_redirects_to_authorize_url(client, monkeypatch):
    async def fake_drive_login(cfg, sess, **kwargs):
        # Stand in for the provider's redirect_handler.
        sess.authorize_url.set_result("https://idp.example.test/authorize?state=abc")
        hermes.SESSIONS["abc"] = sess

    monkeypatch.setattr(hermes, "drive_login", fake_drive_login)
    resp = client.get("/mcp/imcontact/login")
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://idp.example.test/authorize")


def test_login_passes_force_through(client, monkeypatch):
    seen = {}

    async def fake_drive_login(cfg, sess, *, force=False, provider_timeout=300.0):
        seen["force"] = force
        sess.authorize_url.set_result("https://idp.example.test/authorize?state=abc")

    monkeypatch.setattr(hermes, "drive_login", fake_drive_login)

    client.get("/mcp/imcontact/login")
    assert seen["force"] is False
    resp = client.get("/mcp/imcontact/login", params={"force": "true"})
    assert resp.status_code == 302
    assert seen["force"] is True


def test_login_refuses_cross_site(client, monkeypatch):
    called = []

    async def fake_drive_login(cfg, sess, **kwargs):
        called.append(True)
        sess.authorize_url.set_result("https://idp.example.test/authorize?state=abc")

    monkeypatch.setattr(hermes, "drive_login", fake_drive_login)
    resp = client.get("/mcp/imcontact/login", headers={"sec-fetch-site": "cross-site"})
    assert resp.status_code == 403
    assert called == []  # flow never started


def test_index_reauth_link_forces(client, monkeypatch):
    monkeypatch.setattr(hermes, "token_present", lambda name: True)
    resp = client.get("/")
    assert "/mcp/imcontact/login?force=true" in resp.text
    assert ">re-auth<" in resp.text


def test_index_renders_status_banner(client):
    resp = client.get("/", params={"status": "fail", "server": "imcontact",
                                    "detail": "boom <x>"})
    assert "login failed" in resp.text
    assert "boom &lt;x&gt;" in resp.text  # detail is HTML-escaped at render


def test_callback_unknown_state(client):
    resp = client.get("/mcp/imcontact/callback", params={"code": "x", "state": "missing"})
    assert resp.status_code == 400


def test_callback_handler_couples_to_code_result():
    """The provider's callback_handler must receive exactly what /callback sets
    on ``code_result`` — the core coupling between the two HTTP requests."""

    async def scenario():
        loop = asyncio.get_running_loop()
        sess = hermes.LoginSession(
            name="imcontact",
            redirect_uri="https://agent.example.test/mcp/imcontact/callback",
            authorize_url=loop.create_future(),
            code_result=loop.create_future(),
        )

        # Stand-in for drive_login's callback_handler: awaits code_result.
        async def callback_handler():
            return await sess.code_result

        waiter = asyncio.create_task(callback_handler())
        await asyncio.sleep(0)  # let it start waiting

        # What /callback does:
        sess.code_result.set_result(("the-code", "st8"))
        return await waiter

    assert asyncio.run(scenario()) == ("the-code", "st8")
