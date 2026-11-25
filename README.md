# Sentinel

Sentinel is a small SSH intrusion detection and response system built for the "Introduction to Cyber Security" course final project. It watches SSH authentication logs in real time, detects brute-force login attempts, and automatically blocks offending IPs with the Linux firewall — on top of a Django web dashboard that deliberately demonstrates (and fixes) 5 OWASP Top 10 security flaws.

## Features

- Real-time SSH log monitoring via a long-running agent (`monitor_server` management command), running as a systemd service
- Sliding-window brute-force detection, both in batch (`detect_brute_force`) and live/real-time modes
- Automatic IP blocking using the real `ufw` firewall
- A Django dashboard to view monitored servers, login attempts, and blocked IPs
- Encryption at rest for stored SSH credentials (Fernet / `cryptography`)
- An audit log of logins and server views (`AccessLog`)
- A `paramiko`-based attack simulator script to generate realistic brute-force traffic for testing
- 13 automated tests covering log parsing, brute-force detection, the real-time agent logic, and the login lockout

## Security flaws demonstrated

Each flaw below is implemented in the code with the vulnerable version commented out and the fix active, and documented with before/after screenshots in `screenshots/`.

| # | OWASP category | Where | Summary |
|---|---|---|---|
| 1 | Injection | `monitoring/views.py` — `server_detail_view` | Raw string-concatenated SQL query for the log search box → fixed with parameterized Django ORM filtering (`models.Q`) |
| 2 | Broken Access Control | `monitoring/views.py` — `server_detail_view` | Server lookup by `id` only, no ownership check → fixed with `get_object_or_404(..., owner=request.user)` |
| 3 | Identification and Authentication Failures | `monitoring/views.py` — `login_view` | No limit on login attempts → fixed with a server-side `LoginAttempt` record per failed try, keyed by IP address, so the lockout can't be bypassed by dropping the session cookie |
| 4 | Security Logging and Monitoring Failures | `monitoring/views.py` — `login_view`, `server_detail_view` | Logins, failed attempts, lockouts and server views were never recorded → fixed with an `AccessLog` model (actions: `login`, `login_failed`, `login_blocked`, `view_server`) and an audit view |
| 5 | Cryptographic Failures | `monitoring/models.py` — `MonitoredServer` | SSH credentials stored in plaintext → fixed with Fernet symmetric encryption, key kept outside the repo in `.env` |

## Quick start

```bash
git clone https://github.com/rsomavi/sentinel.git
cd sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create your local environment file from the template and set your own encryption key:

```bash
cp src/.env.example src/.env
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# paste the generated key into src/.env as SENTINEL_ENCRYPTION_KEY=...
```

Run migrations and create an admin user:

```bash
cd src
python manage.py migrate
python manage.py createsuperuser
```

Start the development server:

```bash
python manage.py runserver
```

Visit `http://127.0.0.1:8000/login/` and log in.

## Running tests

```bash
cd src
python manage.py test
```

All 13 tests should pass, covering log parsing, batch brute-force detection, the real-time monitoring agent, and the server-side login lockout.

## See it in action (real-time demo)

1. Add a `MonitoredServer` for your own machine through the Django admin (`/admin/`). The hostname field is just a label shown in the dashboard; the SSH credentials field goes through `set_ssh_credentials()` and is stored encrypted (see `monitoring/admin.py`).
2. Start the live monitoring agent, pointed at your system's SSH auth log. **Note the argument order: the log file comes first, then the server name** (it matches the name you gave the `MonitoredServer` above):

   ```bash
   python manage.py monitor_server /var/log/auth.log "<server name>"
   ```

3. In another terminal, simulate a brute-force attack with a password list file as the only argument:

   ```bash
   python scripts/simulate_attack.py ../sample_data/common_passwords.txt
   ```

   By default the script attacks `localhost` as user `ruben` (both hardcoded as constants at the top of `scripts/simulate_attack.py`). To test against a different host/user, edit `TARGET` and `USERNAME` there, or point it at a real test SSH server you control.

4. Watch the agent's terminal output: it parses each failed attempt as it's written, and once the threshold is reached it calls `ufw` to block the attacking IP in real time.

   **Limitation:** loopback addresses (`127.0.0.1`, `::1`) are deliberately excluded from `ufw` blocking (see `LOCALHOST_IPS` in `monitor_server.py`), since blocking your own loopback would be pointless and could lock you out of the machine. This means step 3 above won't trigger an actual firewall rule if you're attacking `localhost` on the same machine that's running the agent — it's still useful to see the detection/logging work, but to see the real `ufw` block in action you need to attack a non-loopback IP (for example, a separate VM or container).
5. Refresh the server's detail page in the dashboard to see the new log entries and the blocked IP.

## Running as a systemd service

A unit file template is provided at `deploy/sentinel-agent.service.example`. Copy it, fill in your real paths, and install it:

```bash
cp deploy/sentinel-agent.service.example deploy/sentinel-agent.service
# edit deploy/sentinel-agent.service with your real project path, venv path and log path
sudo cp deploy/sentinel-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-agent
sudo systemctl start sentinel-agent
```

Check it's running and follow its output:

```bash
sudo systemctl status sentinel-agent
sudo journalctl -u sentinel-agent -f
```

Because the agent calls `ufw` to block IPs, it needs passwordless `sudo` for that one binary only. Configure it with `sudo visudo -f /etc/sudoers.d/sentinel-agent` and restrict the rule to the `ufw` executable — never grant blanket `sudo` access.

## Project structure

```
sentinel/
├── src/
│   ├── config/                  # Django project settings
│   ├── monitoring/
│   │   ├── models.py            # MonitoredServer, LogEntry, BlockedIP, AccessLog
│   │   ├── views.py             # Dashboard, login, server detail, access log views
│   │   ├── urls.py
│   │   ├── tests.py             # 13 automated tests
│   │   ├── templates/monitoring/
│   │   └── management/commands/
│   │       ├── monitor_server.py     # Real-time log-watching agent
│   │       ├── detect_brute_force.py # Batch sliding-window detection
│   │       └── parse_auth_log.py     # Batch log parser
│   ├── .env.example              # Encryption key template (real .env is gitignored)
│   └── manage.py
├── scripts/
│   └── simulate_attack.py        # paramiko-based SSH brute-force simulator
├── sample_data/
│   ├── sample_auth.log           # Realistic sample SSH auth log
│   └── common_passwords.txt      # Sample password list for the simulator
├── deploy/
│   └── sentinel-agent.service.example  # systemd unit file template
├── screenshots/                  # Before/after screenshots for each flaw
└── requirements.txt
```

## Tech stack

- Python 3 / Django
- SQLite (default Django database)
- `cryptography` (Fernet encryption)
- `python-dotenv` (environment variable management)
- `paramiko` (SSH client, for the attack simulator)
- `ufw` (Linux firewall)
- `systemd` (service management)