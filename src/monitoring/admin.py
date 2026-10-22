from django.contrib import admin
from .models import MonitoredServer, LogEntry, BlockedIP


@admin.register(MonitoredServer)
class MonitoredServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'hostname', 'owner')


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'server', 'ip_address', 'username', 'success')
    list_filter = ('success', 'server')


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'server', 'blocked_at', 'reason')