import re
import time
import subprocess
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from monitoring.models import MonitoredServer, LogEntry, BlockedIP



LOG_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'\S+\s+sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+'
    r'(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

REPEATED_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'\S+\s+sshd\[\d+\]:\s+message repeated\s+(?P<count>\d+)\s+times:\s+\[\s*(?P<inner>.+)\]'
)

FAILED_ATTEMPTS_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60
LOCALHOST_IPS = {'127.0.0.1', '::1'}


class Command(BaseCommand):
    help = 'Monitor an SSH auth log file in real time and detect brute force attacks'

    def add_arguments(self, parser):
        parser.add_argument('log_file', type=str)
        parser.add_argument('server_name', type=str)

    def handle(self, *args, **options):
        log_file = options['log_file']
        server_name = options['server_name']

        try:
            server = MonitoredServer.objects.get(name=server_name)
        except MonitoredServer.DoesNotExist:
            self.stderr.write(f'No server found with name "{server_name}"')
            return

        self.stdout.write(self.style.SUCCESS(f'Monitoring {log_file} for server "{server_name}"...'))

        with open(log_file) as f:
            f.seek(0, 2)  # go to the end of the file

            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                self.process_line(line, server)

    def process_line(self, line, server):
        repeated_match = REPEATED_PATTERN.match(line)
        if repeated_match:
            count = int(repeated_match.group('count'))
            prefix = f"{repeated_match.group('month')} {repeated_match.group('day')} {repeated_match.group('time')} MSI sshd[0]: "
            inner_line = prefix + repeated_match.group('inner')
            for _ in range(count):
                self.parse_and_save(inner_line, server)
            return

        self.parse_and_save(line, server)

    def parse_and_save(self, line, server):
        match = LOG_PATTERN.match(line)
        if not match:
            return

        data = match.groupdict()
        ts = self.parse_timestamp(data['month'], data['day'], data['time'])
        success = data['status'] == 'Accepted'

        entry = LogEntry.objects.create(
            server=server,
            timestamp=ts,
            ip_address=data['ip'],
            username=data['username'],
            success=success,
            raw_line=line.strip(),
        )

        self.stdout.write(f'New entry: {entry}')

        if not success:
            self.check_brute_force(server, data['ip'])


    def check_brute_force(self, server, ip):
        already_blocked = BlockedIP.objects.filter(server=server, ip_address=ip).exists()
        if already_blocked:
            return

        recent_window = timezone.now() - timedelta(seconds=TIME_WINDOW_SECONDS)
        recent_failures = LogEntry.objects.filter(
            server=server,
            ip_address=ip,
            success=False,
            timestamp__gte=recent_window,
        ).count()

        if recent_failures >= FAILED_ATTEMPTS_THRESHOLD:
            BlockedIP.objects.create(
                server=server,
                ip_address=ip,
                reason=f'{recent_failures} failed login attempts in the last {TIME_WINDOW_SECONDS}s',
            )
            self.stdout.write(self.style.WARNING(f'BLOCKED {ip} after {recent_failures} failures'))

            if ip not in LOCALHOST_IPS:
                self.block_with_firewall(ip)
            else:
                self.stdout.write(self.style.NOTICE(f'Skipping firewall rule for {ip} (localhost)'))


    def block_with_firewall(self, ip):
        try:
            result = subprocess.run(
                ['sudo', 'ufw', 'deny', 'from', ip],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self.stdout.write(self.style.SUCCESS(f'Firewall rule added for {ip}'))
            else:
                self.stderr.write(f'ufw failed for {ip}: {result.stderr}')
        except Exception as e:
            self.stderr.write(f'Error running ufw for {ip}: {e}')

    def parse_timestamp(self, month, day, time_str):
        current_year = timezone.now().year
        dt_str = f'{current_year} {month} {day} {time_str}'
        naive_dt = datetime.strptime(dt_str, '%Y %b %d %H:%M:%S')
        return timezone.make_aware(naive_dt)
