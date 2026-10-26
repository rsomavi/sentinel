import tempfile
import os

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.management import call_command
from .models import MonitoredServer, LogEntry
from datetime import timedelta
from django.utils import timezone
from .models import BlockedIP
from monitoring.management.commands.monitor_server import Command as MonitorCommand



class ParseAuthLogTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.server = MonitoredServer.objects.create(
            owner=self.user,
            name='Test Server',
            hostname='localhost',
        )

    def write_temp_log(self, content):
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_parses_failed_login_with_invalid_user(self):
        log_content = (
            'Oct 22 09:15:01 MSI sshd[1001]: Failed password for invalid user '
            'admin from 185.220.101.5 port 54321 ssh2\n'
        )
        log_file = self.write_temp_log(log_content)

        call_command('parse_auth_log', log_file, self.server.name)
        os.unlink(log_file)

        self.assertEqual(LogEntry.objects.count(), 1)
        entry = LogEntry.objects.first()
        self.assertEqual(entry.ip_address, '185.220.101.5')
        self.assertEqual(entry.username, 'admin')
        self.assertFalse(entry.success)

    def test_parses_accepted_login(self):
        log_content = (
            'Oct 22 09:20:00 MSI sshd[1009]: Accepted password for ruben '
            'from 192.168.1.10 port 54400 ssh2\n'
        )
        log_file = self.write_temp_log(log_content)

        call_command('parse_auth_log', log_file, self.server.name)
        os.unlink(log_file)

        entry = LogEntry.objects.first()
        self.assertEqual(entry.username, 'ruben')
        self.assertEqual(entry.ip_address, '192.168.1.10')
        self.assertTrue(entry.success)

    def test_skips_unparseable_lines(self):
        log_content = 'this is not a valid log line\n'
        log_file = self.write_temp_log(log_content)

        call_command('parse_auth_log', log_file, self.server.name)
        os.unlink(log_file)

        self.assertEqual(LogEntry.objects.count(), 0)

    def test_multiple_entries_from_same_ip(self):
        log_content = (
            'Oct 22 09:15:01 MSI sshd[1001]: Failed password for invalid user '
            'admin from 185.220.101.5 port 54321 ssh2\n'
            'Oct 22 09:15:03 MSI sshd[1002]: Failed password for invalid user '
            'root from 185.220.101.5 port 54322 ssh2\n'
        )
        log_file = self.write_temp_log(log_content)

        call_command('parse_auth_log', log_file, self.server.name)
        os.unlink(log_file)

        self.assertEqual(LogEntry.objects.count(), 2)
        self.assertEqual(
            LogEntry.objects.filter(ip_address='185.220.101.5').count(), 2
        )


class DetectBruteForceTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.server = MonitoredServer.objects.create(
            owner=self.user,
            name='Test Server',
            hostname='localhost',
        )

    def create_entries(self, ip, count, seconds_apart, success=False):
        base_time = timezone.now()
        for i in range(count):
            LogEntry.objects.create(
                server=self.server,
                timestamp=base_time + timedelta(seconds=i * seconds_apart),
                ip_address=ip,
                username='admin',
                success=success,
            )

    def test_blocks_ip_with_many_fast_failures(self):
        self.create_entries('185.220.101.5', count=8, seconds_apart=2)

        call_command('detect_brute_force', self.server.name)

        self.assertTrue(
            BlockedIP.objects.filter(server=self.server, ip_address='185.220.101.5').exists()
        )

    def test_does_not_block_ip_with_few_failures(self):
        self.create_entries('45.142.120.8', count=2, seconds_apart=2)

        call_command('detect_brute_force', self.server.name)

        self.assertFalse(
            BlockedIP.objects.filter(server=self.server, ip_address='45.142.120.8').exists()
        )

    def test_does_not_block_ip_with_slow_spread_failures(self):
        self.create_entries('1.2.3.4', count=5, seconds_apart=3600)

        call_command('detect_brute_force', self.server.name)

        self.assertFalse(
            BlockedIP.objects.filter(server=self.server, ip_address='1.2.3.4').exists()
        )

    def test_does_not_block_twice(self):
        self.create_entries('185.220.101.5', count=8, seconds_apart=2)

        call_command('detect_brute_force', self.server.name)
        call_command('detect_brute_force', self.server.name)

        self.assertEqual(
            BlockedIP.objects.filter(server=self.server, ip_address='185.220.101.5').count(), 1
        )


class MonitorServerLogicTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.server = MonitoredServer.objects.create(
            owner=self.user,
            name='Test Server',
            hostname='localhost',
        )
        self.cmd = MonitorCommand()

    def test_parses_single_line_and_saves_entry(self):
        line = 'Oct 26 16:43:00 MSI sshd[1234]: Failed password for ruben from 127.0.0.1 port 50000 ssh2\n'
        self.cmd.process_line(line, self.server)
        self.assertEqual(LogEntry.objects.count(), 1)

    def test_expands_repeated_message_line(self):
        line = (
            'Oct 26 16:43:00 MSI sshd[1234]: message repeated 3 times: '
            '[ Failed password for ruben from 127.0.0.1 port 50000 ssh2]\n'
        )
        self.cmd.process_line(line, self.server)
        self.assertEqual(LogEntry.objects.count(), 3)

    def test_blocks_ip_after_threshold_reached_in_realtime(self):
        line_template = 'Oct 26 16:43:{:02d} MSI sshd[1234]: Failed password for ruben from 9.9.9.9 port 50000 ssh2\n'
        for i in range(5):
            self.cmd.process_line(line_template.format(i), self.server)

        self.assertTrue(
            BlockedIP.objects.filter(server=self.server, ip_address='9.9.9.9').exists()
        )