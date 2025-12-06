import json
import sys
from pathlib import Path

# Add project root (parent of "tests") to sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agent


def test_build_domain_from_label():
    labels = {
        agent.LABEL_DOMAIN: "custom.domain.test"
    }
    domain = agent._build_domain("mycontainer", labels)
    assert domain == "custom.domain.test"


def test_build_domain_default(monkeypatch):
    monkeypatch.setattr(agent, "DOCKDNS_DOMAIN", "home.box")
    labels = {}
    domain = agent._build_domain("mycontainer", labels)
    assert domain == "mycontainer.home.box"


def test_generate_traefik_config_empty():
    cfg = agent.generate_traefik_config([])
    assert cfg == {}  # no http section when no containers


def test_generate_traefik_config_single():
    containers = [
        {
            "name": "myapp",
            "domain": "myapp.home.box",
            "port": 8080,
            "container_ip": "172.18.0.5",
        }
    ]
    cfg = agent.generate_traefik_config(containers)

    assert "http" in cfg
    http_cfg = cfg["http"]
    assert "routers" in http_cfg
    assert "services" in http_cfg

    assert "myapp" in http_cfg["routers"]
    router = http_cfg["routers"]["myapp"]
    assert router["rule"] == "Host(`myapp.home.box`)"
    assert router["entryPoints"] == ["web"]
    assert router["service"] == "myapp"

    assert "myapp" in http_cfg["services"]
    svc = http_cfg["services"]["myapp"]
    servers = svc["loadBalancer"]["servers"]
    assert servers == [{"url": "http://172.18.0.5:8080"}]


def test_sync_pihole_adds_records_for_this_host(monkeypatch, tmp_path):
    """
    If no DNS records exist yet, sync_pihole should create records for this host.
    """
    host_ip = "192.168.50.50"
    containers = [
        {"domain": "app1.home.box"},
        {"domain": "app2.home.box"},
    ]

    # Pretend we have a token+url
    monkeypatch.setattr(agent, "PIHOLE_URL", "http://pihole")
    monkeypatch.setattr(agent, "PIHOLE_APP_TOKEN", "token")

    # Fake Pi-hole functions
    created = []

    def fake_get_sid():
        return "SID"

    def fake_list_hosts(sid):
        return []  # no existing records

    def fake_ensure(ip, domain, sid):
        created.append((ip, domain, sid))
        return True

    def fake_delete(ip, domain, sid):
        raise AssertionError("delete should not be called in this scenario")

    monkeypatch.setattr(agent, "pihole_get_sid", fake_get_sid)
    monkeypatch.setattr(agent, "pihole_list_hosts", fake_list_hosts)
    monkeypatch.setattr(agent, "pihole_ensure_record", fake_ensure)
    monkeypatch.setattr(agent, "pihole_delete_record", fake_delete)

    state_file = tmp_path / "state.json"
    monkeypatch.setattr(agent, "DOCKDNS_STATE_FILE", state_file)

    agent.sync_pihole(containers, host_ip)

    assert set(created) == {
        (host_ip, "app1.home.box", "SID"),
        (host_ip, "app2.home.box", "SID"),
    }
    # state file should record managed domains
    data = json.loads(state_file.read_text())
    assert set(data["managed_domains"]) == {"app1.home.box", "app2.home.box"}


def test_sync_pihole_does_not_steal_domain(monkeypatch, tmp_path):
    """
    If a domain already belongs to a different IP, this host should not claim it.
    """
    host_ip = "192.168.50.50"
    containers = [
        {"domain": "shared.home.box"},
    ]

    monkeypatch.setattr(agent, "PIHOLE_URL", "http://pihole")
    monkeypatch.setattr(agent, "PIHOLE_APP_TOKEN", "token")

    created = []
    deleted = []

    def fake_get_sid():
        return "SID"

    def fake_list_hosts(sid):
        # domain already used by another host
        return [("192.168.50.60", "shared.home.box")]

    def fake_ensure(ip, domain, sid):
        created.append((ip, domain, sid))

    def fake_delete(ip, domain, sid):
        deleted.append((ip, domain, sid))

    monkeypatch.setattr(agent, "pihole_get_sid", fake_get_sid)
    monkeypatch.setattr(agent, "pihole_list_hosts", fake_list_hosts)
    monkeypatch.setattr(agent, "pihole_ensure_record", fake_ensure)
    monkeypatch.setattr(agent, "pihole_delete_record", fake_delete)

    monkeypatch.setattr(agent, "DOCKDNS_STATE_FILE", tmp_path / "state.json")

    agent.sync_pihole(containers, host_ip)

    # No record should be created for this host
    assert created == []
    # Nothing should be deleted either
    assert deleted == []


def test_sync_pihole_deletes_stale_records(monkeypatch, tmp_path):
    """
    If a domain for this host exists but the container is gone,
    sync_pihole should delete the DNS record.
    """
    host_ip = "192.168.50.50"
    # Currently running containers: only app1
    containers = [
        {"domain": "app1.home.box"},
    ]

    monkeypatch.setattr(agent, "PIHOLE_URL", "http://pihole")
    monkeypatch.setattr(agent, "PIHOLE_APP_TOKEN", "token")

    ensured = []
    deleted = []

    def fake_get_sid():
        return "SID"

    def fake_list_hosts(sid):
        # app1 + app2 currently exist in Pi-hole for this host
        return [
            (host_ip, "app1.home.box"),
            (host_ip, "app2.home.box"),
        ]

    def fake_ensure(ip, domain, sid):
        ensured.append((ip, domain, sid))
        return True

    def fake_delete(ip, domain, sid):
        deleted.append((ip, domain, sid))
        return True

    monkeypatch.setattr(agent, "pihole_get_sid", fake_get_sid)
    monkeypatch.setattr(agent, "pihole_list_hosts", fake_list_hosts)
    monkeypatch.setattr(agent, "pihole_ensure_record", fake_ensure)
    monkeypatch.setattr(agent, "pihole_delete_record", fake_delete)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"managed_domains": ["app1.home.box", "app2.home.box"]}))
    monkeypatch.setattr(agent, "DOCKDNS_STATE_FILE", state_file)

    agent.sync_pihole(containers, host_ip)

    # app1 should be ensured, app2 should be deleted
    assert (host_ip, "app1.home.box", "SID") in ensured
    assert (host_ip, "app2.home.box", "SID") in deleted

    # state should retain only app1
    data = json.loads(state_file.read_text())
    assert data["managed_domains"] == ["app1.home.box"]


def test_sync_pihole_leaves_unmanaged_records(monkeypatch, tmp_path):
    """
    Manual record pointing to host_ip should not be removed if agent never created it.
    """
    host_ip = "192.168.50.50"
    containers = []  # no containers claim the domain

    monkeypatch.setattr(agent, "PIHOLE_URL", "http://pihole")
    monkeypatch.setattr(agent, "PIHOLE_APP_TOKEN", "token")

    deleted = []

    def fake_get_sid():
        return "SID"

    def fake_list_hosts(sid):
        # Manual record exists for this host IP
        return [(host_ip, "nuc.home.box")]

    def fake_delete(ip, domain, sid):
        deleted.append((ip, domain, sid))
        return True

    monkeypatch.setattr(agent, "pihole_get_sid", fake_get_sid)
    monkeypatch.setattr(agent, "pihole_list_hosts", fake_list_hosts)
    monkeypatch.setattr(agent, "pihole_delete_record", fake_delete)
    monkeypatch.setattr(agent, "DOCKDNS_STATE_FILE", tmp_path / "state.json")

    agent.sync_pihole(containers, host_ip)

    # Manual record should be untouched
    assert deleted == []


def test_snapshot_state_sorted():
    containers = [
        {"domain": "b.example", "container_ip": "10.0.0.2", "port": 80},
        {"domain": "a.example", "container_ip": "10.0.0.1", "port": 81},
    ]

    snapshot = agent._snapshot_state(containers)
    assert snapshot == [
        ("a.example", "10.0.0.1", 81),
        ("b.example", "10.0.0.2", 80),
    ]


def test_should_handle_event_filters():
    handle = {
        "Type": "container",
        "Action": "start",
    }
    ignore_wrong_type = {"Type": "network", "Action": "start"}
    ignore_other_action = {"Type": "container", "Action": "exec_start"}

    assert agent._should_handle_event(handle) is True
    assert agent._should_handle_event(ignore_wrong_type) is False
    assert agent._should_handle_event(ignore_other_action) is False


def test_status_api_reports_containers(monkeypatch):
    containers = [
        {
            "id": "abc123",
            "name": "my.app",
            "domain": "my.app.home.box",
            "port": 8080,
            "container_ip": "172.18.0.5",
            "network": "bridge",
        }
    ]

    traefik_cfg = agent.generate_traefik_config(containers)
    agent._set_status("192.168.1.1", containers, traefik_cfg)

    app = agent.create_status_app()
    client = app.test_client()
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["host_ip"] == "192.168.1.1"
    assert data["containers"][0]["name"] == "my.app"
    assert data["containers"][0]["traefik"]["router"] == "my-app"
    assert data["containers"][0]["traefik"]["rule"] == "Host(`my.app.home.box`)"
