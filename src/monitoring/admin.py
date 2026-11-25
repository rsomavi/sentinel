from django import forms
from django.contrib import admin
from .models import MonitoredServer, LogEntry, BlockedIP


class MonitoredServerAdminForm(forms.ModelForm):
    """
    Custom admin form: the raw ssh_credentials field is never edited
    directly. Instead, the admin types the plaintext here, and this
    form calls set_ssh_credentials() so it actually goes through the
    encryption step defined on the model (FLAW 5 fix).
    """
    ssh_password = forms.CharField(
        label='SSH credentials (plaintext)',
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text='Leave blank to keep the currently stored value.',
    )

    class Meta:
        model = MonitoredServer
        fields = ('owner', 'name', 'hostname')

    def save(self, commit=True):
        instance = super().save(commit=False)
        plaintext = self.cleaned_data.get('ssh_password')
        if plaintext:
            instance.set_ssh_credentials(plaintext)
        if commit:
            instance.save()
        return instance


@admin.register(MonitoredServer)
class MonitoredServerAdmin(admin.ModelAdmin):
    form = MonitoredServerAdminForm
    list_display = ('name', 'hostname', 'owner')


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'server', 'ip_address', 'username', 'success')
    list_filter = ('success', 'server')


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'server', 'blocked_at', 'reason')