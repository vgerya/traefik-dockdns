import os
import time
import subprocess
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


def discover_dockdns_containers():
    """
    Discover containers that have dockdns.enable=true and gather:
      - domain
      - port
      - container_ip
      - network
      - name
      - id
    """
    client = docker.from_env()
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


# -----------------------
# Traefik dynamic config
# -----------------------

def generate_traefik_config(containers):
    """
    Build Traefik 'file provider' config for discovered containers.
    HTTP only, entryPoint 'web'.
    """
    if not containers:
        # No HTTP config when no containers.
        # Traefik is happy with an empty file / empty mapping.
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


def write_traefik_config(containers):
    """
    Write the Traefik dynamic configuration file atomically.

    - If there are no containers, writes a minimal, valid config (or empty mapping).
    - Uses a temp file + atomic rename so Traefik never sees a half-written file.
    """
    cfg = generate_traefik_config(containers)
    TRAEFIK_DYNAMIC_FILE.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = TRAEFIK_DYNAMIC_FILE.with_suffix(".yaml.tmp")

    # When cfg is {}, Traefik simply treats it as "no dynamic HTTP config".
    with tmp_path.open("w") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False)

    # Atomic rename: Traefik will either see the old file or the new file, never a partial write
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

    Expected JSON (simplified):
      {
        "session": {
          "valid": true,
          "sid": "...",
          "message": "..."
        }
      }
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


def sync_pihole(containers, host_ip):
    """
    For each dockdns-enabled container on this host, ensure Pi-hole has:
        host_ip domain
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

    for c in containers:
        domain = c["domain"]
        pihole_ensure_record(host_ip, domain, sid)


# -----------------------
# Main loop
# -----------------------

def main_loop(interval=15):
    host_ip = get_host_lan_ip()
    print(f"[dockdns] Host LAN IP detected: {host_ip}")
    last_state = None

    while True:
        try:
            containers = discover_dockdns_containers()
            new_state = sorted(
                (c["domain"], c["container_ip"], c["port"]) for c in containers
            )

            if new_state != last_state:
                print("[dockdns] Changes detected, syncing...")
                sync_pihole(containers, host_ip)
                write_traefik_config(containers)
                last_state = new_state
            else:
                print("[dockdns] No changes.")

        except Exception as e:
            print("[dockdns] Error in main loop:", e)

        time.sleep(interval)


if __name__ == "__main__":
    poll_interval = int(os.getenv("DOCKDNS_INTERVAL", "15"))
    main_loop(poll_interval)
