from datetime import timedelta
from django.core.management.base import BaseCommand
from django.db.models import Count
from monitoring.models import MonitoredServer, LogEntry, BlockedIP


FAILED_ATTEMPTS_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


class Command(BaseCommand):
    help = 'Detect brute force SSH attacks and block offending IPs'

    def add_arguments(self, parser):
        parser.add_argument('server_name', type=str)

    def handle(self, *args, **options):
        server_name = options['server_name']

        try:
            server = MonitoredServer.objects.get(name=server_name)
        except MonitoredServer.DoesNotExist:
            self.stderr.write(f'No server found with name "{server_name}"')
            return

        failed_entries = LogEntry.objects.filter(server=server, success=False).order_by('ip_address', 'timestamp')

        ip_attempts = {}
        for entry in failed_entries:
            ip_attempts.setdefault(entry.ip_address, []).append(entry.timestamp)

        blocked_count = 0

        for ip, timestamps in ip_attempts.items():
            if self.is_brute_force(timestamps):
                already_blocked = BlockedIP.objects.filter(server=server, ip_address=ip).exists()
                if not already_blocked:
                    BlockedIP.objects.create(
                        server=server,
                        ip_address=ip,
                        reason=f'{len(timestamps)} failed login attempts detected',
                    )
                    blocked_count += 1
                    self.stdout.write(self.style.WARNING(f'Blocked {ip} ({len(timestamps)} failed attempts)'))

        self.stdout.write(self.style.SUCCESS(f'Done. {blocked_count} new IPs blocked.'))

    def is_brute_force(self, timestamps):
        if len(timestamps) < FAILED_ATTEMPTS_THRESHOLD:
            return False

        timestamps = sorted(timestamps)

        for i in range(len(timestamps) - FAILED_ATTEMPTS_THRESHOLD + 1):
            window_start = timestamps[i]
            window_end = timestamps[i + FAILED_ATTEMPTS_THRESHOLD - 1]
            if (window_end - window_start) <= timedelta(seconds=TIME_WINDOW_SECONDS):
                return True

        return False
