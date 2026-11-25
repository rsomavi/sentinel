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
    #
    # Note: the field is called "ssh_credentials" in BOTH the flaw and
    # the fix state on purpose, so toggling between them never requires
    # a new migration - only the code inside these two methods changes.
    ssh_credentials = models.CharField(max_length=500, blank=True)

    def set_ssh_credentials(self, plaintext):
        if not plaintext:
            self.ssh_credentials = ''
            return

        # FLAW: store the plaintext as-is.
        # self.ssh_credentials = plaintext

        # FIX: encrypt with Fernet symmetric encryption before storing.
        # The plaintext itself is never written to the database.
        f = Fernet(settings.ENCRYPTION_KEY)
        self.ssh_credentials = f.encrypt(plaintext.encode()).decode()

    def get_ssh_credentials(self):
        if not self.ssh_credentials:
            return ''

        # FLAW: the stored value already is the plaintext.
        # return self.ssh_credentials

        # FIX: decrypt before returning.
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.decrypt(self.ssh_credentials.encode()).decode()

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


class LoginAttempt(models.Model):
    # FIX for FLAW 3 (Authentication Failures): failed login attempts
    # are tracked here, server-side, keyed by IP address - not in
    # request.session, which lives in a cookie the attacker controls
    # (an attacker who simply omits the session cookie would otherwise
    # reset their own counter back to zero on every try).
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.timestamp} failed login for {self.username!r} from {self.ip_address}'