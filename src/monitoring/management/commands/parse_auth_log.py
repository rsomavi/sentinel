import re
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from monitoring.models import MonitoredServer, LogEntry


LOG_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'\S+\s+sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+'
    r'(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)


class Command(BaseCommand):
    help = 'Parse an SSH auth log file and create LogEntry records'

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

        created_count = 0
        skipped_count = 0

        with open(log_file) as f:
            for line in f:
                match = LOG_PATTERN.match(line)
                if not match:
                    skipped_count += 1
                    continue

                data = match.groupdict()
                timestamp = self.parse_timestamp(data['month'], data['day'], data['time'])
                success = data['status'] == 'Accepted'

                LogEntry.objects.create(
                    server=server,
                    timestamp=timestamp,
                    ip_address=data['ip'],
                    username=data['username'],
                    success=success,
                    raw_line=line.strip(),
                )
                created_count += 1

        self.stdout.write(self.style.SUCCESS(
            f'Created {created_count} log entries ({skipped_count} lines skipped)'
        ))

    def parse_timestamp(self, month, day, time):
        current_year = timezone.now().year
        dt_str = f'{current_year} {month} {day} {time}'
        naive_dt = datetime.strptime(dt_str, '%Y %b %d %H:%M:%S')
        return timezone.make_aware(naive_dt)
