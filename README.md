# dockdns

Automatic DNS + reverse proxy wiring for your home lab.

`dockdns` runs **per host** and:

- Watches Docker containers with `dockdns.enable=true`.
- Derives a domain for each container (e.g. `myapp.home.box`).
- Writes Traefik dynamic config (file provider) to route HTTP traffic.
- Manages Pi-hole DNS records so each domain points to the correct host IP.
- Cleans up DNS when containers disappear.
- Avoids stealing domains that are already owned by another host.

Designed for setups like: NUC + TrueNAS + Raspberry Pis + Pi-hole, all under `*.home.box`.

---

## Architecture

Per host, you run a **combined container** that includes:

- Traefik (reverse proxy)
- dockdns agent (Python)

### Components

- **Pi-hole**
  - Central DNS server (e.g. `192.168.50.240`).
  - Manages `A` records like `app1.home.box -> 192.168.50.50`.

- **dockdns agent (per host)**
  - Talks to Docker via `/var/run/docker.sock`.
  - Detects containers with `dockdns.enable=true`.
  - For each such container:
    - Domain:
      - `dockdns.domain` label, or
      - `<container_name>.<DOCKDNS_DOMAIN>` (e.g. `grafana.home.box`).
    - Port:
      - `dockdns.port` label, or
      - first exposed port from `EXPOSE`/Docker config.
  - Writes Traefik config under `/etc/traefik/dynamic/dockdns.yaml`.
  - Talks to Pi-hole v6 API:
    - Uses app token (application password) to `POST /api/auth` → SID.
    - Uses SID for:
      - `GET /api/config/dns/hosts` to list host entries.
      - `PUT /api/config/dns/hosts/IP%20DOMAIN` to create entries.
      - `DELETE /api/config/dns%2Fhosts/IP%20DOMAIN` to delete entries.
  - Exposes a REST status API (`/api/status`) on port `8081` (configurable via `DOCKDNS_API_PORT`) showing running containers and their DNS/Traefik mapping.
  - Tracks which domains it created in Pi-hole (state file: `DOCKDNS_STATE_FILE`, default `/etc/traefik/dockdns-state.json`) and only deletes DNS records it previously created. Manual entries are left untouched.

### DNS Ownership Rules

- Each host uses its **LAN IP** (`HOST_LAN_IP`).
- For each container domain on this host:
  - If domain is **unused** → create `HOST_LAN_IP domain`.
  - If domain is already used by **this host IP** → keep it.
  - If domain is already used by **another IP** → **do not** create/change it.
- If dockdns previously created `HOST_LAN_IP some.domain` but no container on this host uses `some.domain` anymore → that DNS record is deleted.

This prevents two hosts from claiming the same name and cleans up stale names when containers are removed.

---

## Labels

On a container you want exposed:

```yaml
labels:
  - "dockdns.enable=true"
  # optional:
  - "dockdns.domain=grafana.home.box"
  # optional:
  - "dockdns.port=3000"
