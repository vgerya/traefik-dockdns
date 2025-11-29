
# dockdns

Small Python agent that:

- Discovers Docker containers with `dockdns.enable=true`
- Derives domain from label or `<container_name>.<DOCKDNS_DOMAIN>`
- Determines container IP + port (label or first exposed port)
- Writes Traefik dynamic config (file provider)
- (Placeholder) syncs DNS to Pi-hole

## Quickstart with pyenv

```bash
pyenv install 3.12.3   # or latest 3.x you like
pyenv virtualenv 3.12.3 dockdns-venv
pyenv local dockdns-venv

pip install -r requirements.txt

# test discovery (must be on a host with Docker)
python agent.py
```

Environment variables:

- `DOCKDNS_DOMAIN` (default: `home.box`)
- `DOCKDNS_TRAEFIK_FILE` (default: `/etc/traefik/dynamic/dockdns.yaml`)
- `DOCKDNS_INTERVAL` (default: `15` seconds)
