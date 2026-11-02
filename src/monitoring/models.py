from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from cryptography.fernet import Fernet


class MonitoredServer(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    hostname = models.CharField(max_length=255)

    # FLAW 5 (Cryptographic Failures): SSH credentials stored as plain
    # text. Anyone with database read access (a compromised backup, an
    # SQL injection, a careless admin) could read them directly.
    # ssh_credentials = models.CharField(max_length=255, blank=True)

    # FIX: store credentials encrypted at rest using Fernet symmetric
    # encryption. The plaintext is never written to the database.
    ssh_credentials_encrypted = models.CharField(max_length=500, blank=True)

    def set_ssh_credentials(self, plaintext):
        if not plaintext:
            self.ssh_credentials_encrypted = ''
            return
        f = Fernet(settings.ENCRYPTION_KEY)
        self.ssh_credentials_encrypted = f.encrypt(plaintext.encode()).decode()

    def get_ssh_credentials(self):
        if not self.ssh_credentials_encrypted:
            return ''
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.decrypt(self.ssh_credentials_encrypted.encode()).decode()

    def __str__(self):
        return self.name


class LogEntry(models.Model):
    server = models.ForeignKey(MonitoredServer, on_delete=models.CASCADE, related_name='entries')
    timestamp = models.DateTimeField()
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=100)
    success = models.BooleanField(default=False)
    raw_line = models.TextField(blank=True)

    def __str__(self):
        status = 'success' if self.success else 'failed'
        return f'{self.timestamp} {status} {self.username}@{self.ip_address}'


class BlockedIP(models.Model):
    server = models.ForeignKey(MonitoredServer, on_delete=models.CASCADE, related_name='blocked_ips')
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=255)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.ip_address} blocked on {self.server.name}'


class AccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=100)
    detail = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f'{self.timestamp} {self.user} {self.action} {self.detail}'