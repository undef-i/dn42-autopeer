# [WIP] DN42 AutoPeer

Automated DN42 peering management system. Handles WireGuard tunnel setup and BGP configuration through web interface.

## Prerequisites

- Python 3.8+
- WireGuard
- BIRD Internet Routing Daemon
- Git
- A valid DN42 ASN and registry entry

## Installation

```bash
git clone <repository-url>
cd dn42-autopeer
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
python run.py
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

#### Required Configuration

- `RESEND_API_KEY`: API key for Resend email service
- `WIREGUARD_PRIVATE_KEY`: Your WireGuard server private key
- `SECRET_KEY`: Flask secret key for session management

#### Optional Configuration

- `EMAIL_FROM`: Email address for verification emails
- `FLASK_PORT`: Port for the web interface (default: 5009)
- `DATABASE_PATH`: Path to SQLite database file
- `DN42_REGISTRY_URL`: DN42 registry Git URL
- `GIT_USERNAME` / `GIT_TOKEN`: Git credentials for private registry access
- `DEBUG_BYPASS_KEY`: Development bypass key for testing

### Network Configuration

- `WIREGUARD_SERVER_IPV4`: Your server's IPv4 address in DN42
- `WIREGUARD_SERVER_IPV6`: Your server's IPv6 address in DN42
- `WIREGUARD_SERVER_IPV6_LL`: Your server's IPv6 link-local address
- `ALLOWED_IPS`: Comma-separated list of allowed IP ranges

## Usage

### Usage

```bash
python run.py
```

Access web interface at `http://localhost:5000`
