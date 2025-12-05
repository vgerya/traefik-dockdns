import json
import os
import time
import subprocess
import threading
from pathlib import Path
from urllib.parse import quote

import docker
import requests
import yaml


# -----------------------
# Global configuration
# -----------------------

LABEL_ENABLE = "dockdns.enable"
LABEL_DOMAIN = "dockdns.domain"
LABEL_PORT = "dockdns.port"

DOCKDNS_DOMAIN = os.getenv("DOCKDNS_DOMAIN", "home.box")
TRAEFIK_DYNAMIC_FILE = Path(
    os.getenv("DOCKDNS_TRAEFIK_FILE", "/etc/traefik/dynamic/dockdns.yaml")
)

PIHOLE_URL = os.getenv("PIHOLE_URL")              # e.g. http://192.168.50.240
PIHOLE_APP_TOKEN = os.getenv("PIHOLE_APP_TOKEN")  # app password from Pi-hole UI
DOCKDNS_API_PORT = int(os.getenv("DOCKDNS_API_PORT", "8081"))

# -----------------------
# Shared status (for REST API)
# -----------------------

_status_lock = threading.Lock()
_status_payload = {
    "host_ip": None,
    "containers": [],
    "traefik": {},
    "last_sync": None,
}


# -----------------------
# Host IP / environment
# -----------------------

def get_host_lan_ip():
    """
    Returns host LAN IP.

    Priority:
      1. HOST_LAN_IP env var (best when agent runs in Docker)
      2. Fallback: IP used to reach the internet (works with network_mode=host)
    """
    env_ip = os.getenv("HOST_LAN_IP")
    if env_ip:
        return env_ip.strip()

    cmd = "ip route get 1.1.1.1 | awk '{print $7; exit}'"
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    if not out:
        raise RuntimeError("Could not determine host LAN IP")
    return out


# -----------------------
# Docker discovery
# -----------------------

def _get_first_exposed_port(container_attrs):
    """
    Get the first exposed port from Config.ExposedPorts or NetworkSettings.Ports.
    Returns int or None.
    """
    cfg = container_attrs.get("Config", {}) or {}
    exposed = cfg.get("ExposedPorts") or {}

    port = None

    if exposed:
        # ExposedPorts keys look like "8080/tcp"
        first_key = next(iter(exposed.keys()))
        port_str = first_key.split("/")[0]
        if port_str.isdigit():
            port = int(port_str)

    if port is not None:
        return port

    net_settings = container_attrs.get("NetworkSettings", {}) or {}
    ports = net_settings.get("Ports") or {}
    if ports:
        first_key = next(iter(ports.keys()))
        port_str = first_key.split("/")[0]
        if port_str.isdigit():
            return int(port_str)

    return None


def _build_domain(container_name, labels):
    """
    Determine domain for dockdns:
      1. If dockdns.domain label exists -> use it.
      2. Else <container_name>.<DOCKDNS_DOMAIN>
    """
    domain_label = labels.get(LABEL_DOMAIN)
    if domain_label:
        return domain_label.strip()

    if not DOCKDNS_DOMAIN:
        return None

    clean_name = container_name.lstrip("/")
    return f"{clean_name}.{DOCKDNS_DOMAIN}"


def discover_dockdns_containers(client=None):
    """
    Discover containers that have dockdns.enable=true and gather:
      - domain
      - port
      - container_ip
      - network
      - name
      - id
    """
    client = client or docker.from_env()
    containers = client.containers.list()
    result = []

    for c in containers:
        attrs = c.attrs
        labels = attrs.get("Config", {}).get("Labels", {}) or {}

        if labels.get(LABEL_ENABLE, "false").lower() != "true":
            continue

        domain = _build_domain(c.name, labels)
        if not domain:
            print(f"[dockdns] WARNING: cannot determine domain for container {c.name}")
            continue

        port = labels.get(LABEL_PORT)
        if port:
            try:
                port = int(port)
            except ValueError:
                print(f"[dockdns] WARNING: invalid dockdns.port={port!r} on {c.name}")
                port = None

        if port is None:
            port = _get_first_exposed_port(attrs)

        if port is None:
            print(f"[dockdns] WARNING: no port found for {c.name}")
            continue

        networks = attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
        if not networks:
            print(f"[dockdns] WARNING: no networks found for {c.name}")
            continue

        net_name, net_info = next(iter(networks.items()))
        container_ip = net_info.get("IPAddress")

        if not container_ip:
            print(f"[dockdns] WARNING: no IP address for {c.name} on network {net_name}")
            continue

        result.append({
            "id": c.id,
            "name": c.name.lstrip("/"),
            "domain": domain,
            "port": port,
            "container_ip": container_ip,
            "network": net_name,
        })

    return result


def _set_status(host_ip, containers, traefik_cfg):
    """
    Update shared status payload used by the REST API.
    """
    with _status_lock:
        _status_payload["host_ip"] = host_ip
        _status_payload["last_sync"] = time.time()
        _status_payload["traefik"] = traefik_cfg

        detailed = []
        for c in containers:
            name_slug = c["name"].replace(".", "-")
            rule = f"Host(`{c['domain']}`)"
            detailed.append({
                "id": c["id"],
                "name": c["name"],
                "domain": c["domain"],
                "port": c["port"],
                "container_ip": c["container_ip"],
                "network": c["network"],
                "traefik": {
                    "router": name_slug,
                    "service": name_slug,
                    "rule": rule,
                    "target_url": f"http://{c['container_ip']}:{c['port']}",
                },
            })

        _status_payload["containers"] = detailed


def _get_status():
    with _status_lock:
        # Deep copy to avoid exposing internal dict references
        return json.loads(json.dumps(_status_payload))
def _snapshot_state(containers):
    """
    Deterministic view of container state used to detect changes.
    """
    return sorted(
        (c["domain"], c["container_ip"], c["port"]) for c in containers
    )


def create_status_app():
    """
    Build the Flask app that exposes current dockdns state.
    """
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.get("/api/status")
    def api_status():
        return jsonify(_get_status())

    return app


def start_status_api(port):
    """
    Start REST API server in a background thread.
    """
    app = create_status_app()

    def _run():
        app.run(
            host="0.0.0.0",
            port=port,
            debug=False,
            use_reloader=False,
        )

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    print(f"[dockdns] Status API listening on 0.0.0.0:{port}/api/status")
    return thread


# -----------------------
# Traefik dynamic config
# -----------------------

def generate_traefik_config(containers):
    """
    Build Traefik 'file provider' config for discovered containers.
    HTTP only, entryPoint 'web'.
    """
    if not containers:
        # No dynamic HTTP config when no containers.
        return {}

    http_cfg = {
        "routers": {},
        "services": {},
    }

    for c in containers:
        name = c["name"].replace(".", "-")
        domain = c["domain"]
        port = c["port"]
        ip = c["container_ip"]

        router_name = name
        service_name = name

        router_cfg = {
            "rule": f"Host(`{domain}`)",
            "entryPoints": ["web"],
            "service": service_name,
        }

        service_cfg = {
            "loadBalancer": {
                "servers": [
                    {"url": f"http://{ip}:{port}"}
                ]
            }
        }

        http_cfg["routers"][router_name] = router_cfg
        http_cfg["services"][service_name] = service_cfg

    # Wrap in 'http:' as required by Traefik
    return {"http": http_cfg}


def write_traefik_config(containers, cfg=None):
    """
    Write the Traefik dynamic configuration file atomically.

    - If there are no containers, writes a minimal, valid config (or empty mapping).
    - Uses a temp file + atomic rename so Traefik never sees a half-written file.
    """
    cfg = cfg if cfg is not None else generate_traefik_config(containers)
    TRAEFIK_DYNAMIC_FILE.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = TRAEFIK_DYNAMIC_FILE.with_suffix(".yaml.tmp")

    with tmp_path.open("w") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False)

    tmp_path.replace(TRAEFIK_DYNAMIC_FILE)

    print(f"[dockdns] Wrote Traefik config to {TRAEFIK_DYNAMIC_FILE}")


# -----------------------
# Pi-hole v6 integration (app token -> SID)
# -----------------------

def pihole_get_sid():
    """
    Authenticate to Pi-hole using the app token (application password)
    and return a session ID (SID).

    POST /api/auth
    Body: {"password": "<app token>", "totp": null}
    """
    if not PIHOLE_URL or not PIHOLE_APP_TOKEN:
        raise RuntimeError("PIHOLE_URL or PIHOLE_APP_TOKEN not set")

    url = f"{PIHOLE_URL.rstrip('/')}/api/auth"

    payload = {
        "password": PIHOLE_APP_TOKEN,
        "totp": None,
    }

    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
    }

    resp = requests.post(url, json=payload, headers=headers, timeout=5)
    resp.raise_for_status()

    data = resp.json()
    session = data.get("session", {})

    if not session.get("valid"):
        msg = session.get("message") or "unknown error"
        raise RuntimeError(f"Pi-hole auth failed: {msg}")

    sid = session.get("sid")
    if not sid:
        raise RuntimeError("Pi-hole /api/auth returned no SID")

    return sid


def pihole_list_hosts(sid):
    """
    List all custom DNS host entries as (ip, domain) tuples.

    GET /api/config/dns/hosts?sid=<SID>

    Expected JSON (simplified):
      {
        "config": {
          "dns": {
            "hosts": [
              "10.10.10.10 test",
              "192.168.1.1 router.home"
            ]
          }
        },
        "took": ...
      }
    """
    if not PIHOLE_URL:
        return []

    url = f"{PIHOLE_URL.rstrip('/')}/api/config/dns/hosts"
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    params = {"sid": sid}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        resp.raise_for_status()
    except Exception as e:
        print("[dockdns] Error fetching Pi-hole hosts:", e)
        return []

    try:
        data = resp.json()
    except ValueError as e:
        print("[dockdns] Invalid JSON from Pi-hole hosts:", e, resp.text[:200])
        return []

    hosts_list = (
        data.get("config", {})
        .get("dns", {})
        .get("hosts", [])
    ) or []

    result = []
    for entry in hosts_list:
        # Each entry is "IP domain"
        if not isinstance(entry, str):
            continue
        parts = entry.split(" ", 1)
        if len(parts) != 2:
            continue
        ip, domain = parts[0].strip(), parts[1].strip()
        if ip and domain:
            result.append((ip, domain))

    return result


def pihole_ensure_record(ip, domain, sid):
    """
    Ensure Pi-hole has a DNS host record: `ip domain`.

    Uses:
      PUT /api/config/dns/hosts/{ip}%20{domain}?sid=<SID>

    - On 200/201/204: created/updated
    - On 400 with "Item already present": treated as success (idempotent)
    """
    if not PIHOLE_URL:
        print("[dockdns] PIHOLE_URL not set, skipping DNS update")
        return

    path = f"/api/config/dns/hosts/{quote(ip + ' ' + domain)}"
    url = f"{PIHOLE_URL.rstrip('/')}{path}"

    headers = {
        "Accept": "*/*",
        "X-Requested-With": "XMLHttpRequest",
    }

    params = {"sid": sid}

    try:
        resp = requests.put(url, headers=headers, params=params, timeout=5)

        if resp.status_code in (200, 201, 204):
            print(f"[dockdns] Pi-hole host set: {domain} -> {ip}")
            return

        if resp.status_code == 400:
            try:
                data = resp.json()
                err = data.get("error", {})
                msg = (err.get("message") or "").lower()
                key = (err.get("key") or "").lower()
                if key == "bad_request" and "already present" in msg:
                    print(f"[dockdns] Pi-hole host already exists: {domain} -> {ip}")
                    return
            except Exception:
                pass

        print(
            f"[dockdns] Pi-hole PUT failed for {domain} -> {ip}: "
            f"{resp.status_code} {resp.text}"
        )

    except Exception as e:
        print(f"[dockdns] Error talking to Pi-hole for {domain} -> {ip}:", e)


def pihole_delete_record(ip, domain, sid):
    """
    Delete Pi-hole DNS host record `ip domain`.

    Uses generic config endpoint:
      DELETE /api/config/dns%2Fhosts/{ip}%20{domain}?sid=<SID>
    """
    if not PIHOLE_URL:
        print("[dockdns] PIHOLE_URL not set, skipping DNS delete")
        return

    element = quote("dns/hosts", safe="")  # -> dns%2Fhosts
    value = quote(f"{ip} {domain}")
    path = f"/api/config/{element}/{value}"
    url = f"{PIHOLE_URL.rstrip('/')}{path}"

    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    params = {"sid": sid}

    try:
        resp = requests.delete(url, headers=headers, params=params, timeout=5)

        if resp.status_code in (200, 204):
            print(f"[dockdns] Pi-hole host deleted: {domain} -> {ip}")
            return

        if resp.status_code == 404:
            # Already gone – that's fine
            print(f"[dockdns] Pi-hole host already absent: {domain} -> {ip}")
            return

        print(
            f"[dockdns] Pi-hole DELETE failed for {domain} -> {ip}: "
            f"{resp.status_code} {resp.text}"
        )

    except Exception as e:
        print(f"[dockdns] Error deleting Pi-hole record {domain} -> {ip}:", e)


def sync_pihole(containers, host_ip):
    """
    Sync Pi-hole state for this host:

    - For each container on this host, ensure:
        domain -> host_ip
      BUT:
        * If the same domain already exists pointing to a different IP,
          we DO NOT create a new record (avoid domain conflicts).
    - For any existing record pointing to host_ip whose domain is no longer
      used by any container on this host, delete it.
    """
    if not PIHOLE_URL or not PIHOLE_APP_TOKEN:
        print("[dockdns] Pi-hole not configured (PIHOLE_URL/PIHOLE_APP_TOKEN), skipping DNS sync")
        return

    try:
        sid = pihole_get_sid()
        print("[dockdns] Pi-hole SID obtained")
    except Exception as e:
        print("[dockdns] Pi-hole auth failed:", e)
        return

    existing = pihole_list_hosts(sid)
    existing_pairs = set(existing)  # (ip, domain)

    # domain -> set(ips)
    domain_to_ips = {}
    for ip, domain in existing:
        domain_to_ips.setdefault(domain, set()).add(ip)

    desired_domains = {c["domain"] for c in containers}

    # 1) Upsert (respecting domain ownership)
    for c in containers:
        domain = c["domain"]
        ips_for_domain = domain_to_ips.get(domain, set())

        # If domain exists on another IP, don't steal it
        if ips_for_domain and host_ip not in ips_for_domain:
            print(
                f"[dockdns] WARNING: Domain {domain} already used in Pi-hole "
                f"for IP(s) {', '.join(sorted(ips_for_domain))}, "
                f"skipping creation for {host_ip}"
            )
            continue

        # Either the domain is new, or already bound to this host_ip
        pihole_ensure_record(host_ip, domain, sid)

    # 2) Delete stale records belonging to this host
    for ip, domain in existing_pairs:
        if ip != host_ip:
            continue
        if domain in desired_domains:
            continue

        # This host previously owned this domain, but no container claims it now
        print(f"[dockdns] Removing stale DNS record for {domain} -> {ip}")
        pihole_delete_record(ip, domain, sid)


# -----------------------
# Main loop
# -----------------------

def _should_handle_event(event):
    """
    Returns True if this Docker event should trigger a resync.
    """
    if not isinstance(event, dict):
        return False

    if event.get("Type") != "container":
        return False

    action = (event.get("Action") or "").lower()
    watched = {
        "start",
        "stop",
        "die",
        "destroy",
        "kill",
        "pause",
        "unpause",
    }
    return action in watched


def _sync_all(host_ip, last_state=None, client=None):
    """
    Discover current containers, sync DNS + Traefik, and return new state snapshot.
    """
    containers = discover_dockdns_containers(client=client)
    traefik_cfg = generate_traefik_config(containers)
    _set_status(host_ip, containers, traefik_cfg)
    new_state = _snapshot_state(containers)

    if new_state != last_state:
        print("[dockdns] Changes detected, syncing...")
        sync_pihole(containers, host_ip)
        write_traefik_config(containers, cfg=traefik_cfg)
    else:
        print("[dockdns] No changes.")

    return new_state


def main_loop(_interval_unused=15):
    """
    Event-driven loop:
      - initial full sync of running containers
      - listen for container lifecycle events and resync when they occur
    """
    if not PIHOLE_APP_TOKEN:
        raise RuntimeError("PIHOLE_APP_TOKEN not set")
    if not PIHOLE_URL:
        raise RuntimeError("PIHOLE_URL not set")

    host_ip = get_host_lan_ip()
    print(f"[dockdns] Host LAN IP detected: {host_ip}")

    client = docker.from_env()
    start_status_api(DOCKDNS_API_PORT)
    last_state = _sync_all(host_ip, client=client)

    while True:
        try:
            print("[dockdns] Listening for Docker events (start/stop/die/destroy)...")
            for event in client.events(decode=True, filters={"type": "container"}):
                if not _should_handle_event(event):
                    continue

                action = event.get("Action") or "unknown"
                attrs = (event.get("Actor") or {}).get("Attributes") or {}
                name = attrs.get("name") or "unknown"
                print(f"[dockdns] Docker event: {action} for {name}")

                last_state = _sync_all(host_ip, last_state=last_state, client=client)

        except KeyboardInterrupt:
            print("[dockdns] Stopping dockdns agent.")
            return
        except Exception as e:
            print("[dockdns] Error while processing events, retrying in 5s:", e)
            time.sleep(5)
            try:
                client = docker.from_env()
            except Exception as conn_err:
                print("[dockdns] Reconnecting to Docker failed:", conn_err)
                time.sleep(5)


if __name__ == "__main__":
    poll_interval = int(os.getenv("DOCKDNS_INTERVAL", "15"))
    main_loop(poll_interval)
