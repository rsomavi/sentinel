from django.db import models
from django.contrib.auth.models import User


class MonitoredServer(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    hostname = models.CharField(max_length=255)
    ssh_credentials = models.CharField(max_length=255, blank=True)

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