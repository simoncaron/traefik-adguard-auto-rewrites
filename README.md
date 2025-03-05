# Traefik AdGuard Auto Rewrites

Automatically create AdGuard Home Rewrite Rules based on Traefik host rules labels for seamless local domain resolution in your homelab or development environment.

## What it does

This tool monitors Docker containers with Traefik labels and automatically creates corresponding AdGuard rewrite rules in AdGuard Home.

For example, if you have a container with `traefik.http.routers.myapp.rule=Host(\`myapp.local\`)`, this tool will automatically create a rewrite rule in AdGuard Home pointing `myapp.local` to the default configured IP or to a specific IP (using the `adguard.dns.target.override` extra label).

## Features

- Automatic synchronization between Traefik and AdGuard Home
- Real-time updates when containers start, stop, or change
- Configure a default target value for all containers or override per specific container
- Persistent state storage which means it will only manage entires it created

## Installation

### Docker Compose

```yaml
services:
  traefik-adguard-sync:
    image: ghcr.io/simoncaron/traefik-adguard-auto-rewrites:latest
    container_name: traefik-adguard-sync
    environment:
      ADGUARD_USERNAME: your_adguard_username
      ADGUARD_PASSWORD: your_adguard_password
      ADGUARD_API_URL: http://adguard:3000/control
      DEFAULT_DNS_RECORD_TARGET: 192.168.1.100
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./state:/state
    restart: unless-stopped
```

### Environment Variables

| Variable | Description                               | Default |
|----------|-------------------------------------------|---------|
| `ADGUARD_USERNAME` | AdGuard Home username                     | (Required) |
| `ADGUARD_PASSWORD` | AdGuard Home password                     | (Required) |
| `ADGUARD_API_URL` | URL to AdGuard Home API                   | `http://adguard:3000/control` |
| `DEFAULT_DNS_RECORD_TARGET` | Default IP for Rewrite Rules              | (Required) |
| `DOCKER_HOST` | Docker daemon socket                      | `unix://var/run/docker.sock` |
| `LOGGING_LEVEL` | Log verbosity (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `STATE_FILE` | Path to state file                        | `/state/adguard.state` |

## Usage

### Container Labels

To have domains automatically added to AdGuard Home DNS rewrites, add standard Traefik Host rules to your containers:

```yaml
labels:
  - "traefik.http.routers.myapp.rule=Host(`app.local`)"
```

To override the target IP for a specific container (instead of using the valude set for `DEFAULT_DNS_RECORD_TARGET`):

```yaml
labels:
  - "traefik.http.routers.myapp.rule=Host(`app.local`)"
  - "adguard.dns.target.override=192.168.1.150"
```

The tool supports multiple domains in a single rule:

```yaml
labels:
  - "traefik.http.routers.myapp.rule=Host(`app.local`, `www.app.local`)"
```

And complex rules with Host directives:

```yaml
labels:
  - "traefik.http.routers.myapp.rule=Host(`app.local`) || Path(`/api`)"
```

## How It Works

1. On startup, the tool scans all running containers for Traefik Host rules
2. It extracts domain names from the rules and creates DNS rewrites in AdGuard Home
3. It listens for Docker events (container start/stop/update) and updates DNS rewrites accordingly
4. The state is persisted to disk, allowing for clean restarts

## Development

### Requirements

- Python 3.11+
- Docker
- AdGuard Home instance

### Building

```bash
docker build -t traefik-adguard-auto-rewrites .
```

### Testing

```bash
pip install -r requirements-dev.txt
pytest
```
## Credits

- Script inspired by @theonlysinjin Pi-Hole DNS Shim [docker-pihole-dns-shim](https://github.com/theonlysinjin/docker-pihole-dns-shim)
- Repo structure and CI based on @RealOrangeOne [docker-db-auto-backup](https://github.com/RealOrangeOne/docker-db-auto-backup)

## License

MIT