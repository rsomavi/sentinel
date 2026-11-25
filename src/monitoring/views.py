from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.db import connection, models
from django.utils import timezone
from .models import MonitoredServer, LogEntry, BlockedIP, AccessLog, LoginAttempt


import time
from datetime import timedelta

LOGIN_ATTEMPTS_THRESHOLD = 5
LOGIN_LOCKOUT_SECONDS = 60

def get_client_ip(request):
    return request.META.get('REMOTE_ADDR')

def login_view(request):
    # FLAW 3 (Authentication Failures): no limit on login attempts.
    # An attacker can try unlimited username/password combinations
    # without any delay or lockout, making brute-force attacks trivial.
    # if request.method == 'POST':
    #     username = request.POST.get('username')
    #     password = request.POST.get('password')
    #     user = authenticate(request, username=username, password=password)
    #     if user is not None:
    #         login(request, user)
    #         return redirect('dashboard')
    #     return render(request, 'monitoring/login.html', {'error': 'Invalid credentials'})
    # return render(request, 'monitoring/login.html')

    # FIX: count failed attempts server-side, in the LoginAttempt table,
    # keyed by IP address - NOT in request.session. A counter kept in
    # the session lives in a cookie the attacker controls: an attacker
    # who simply stops sending that cookie would reset their own count
    # back to zero on every single try, making the old session-based
    # lockout trivial to bypass. Counting in the database closes that
    # gap, since the server decides what counts as "recent", not the
    # client.
    ip = get_client_ip(request)
    window_start = timezone.now() - timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
    recent_failures = LoginAttempt.objects.filter(
        ip_address=ip, timestamp__gte=window_start
    ).count()

    if recent_failures >= LOGIN_ATTEMPTS_THRESHOLD:
        # FIX for FLAW 4 (Security Logging and Monitoring Failures):
        # a blocked attempt is itself worth recording, since it is
        # the clearest sign that someone is actively being locked out.
        AccessLog.objects.create(
            user=None,
            action='login_blocked',
            detail=f'ip={ip}',
            ip_address=ip,
        )
        return render(request, 'monitoring/login.html', {
            'error': f'Too many failed attempts. Try again in {LOGIN_LOCKOUT_SECONDS} seconds.'
        })

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # FLAW 4 (Security Logging Failures): successful logins are
            # never recorded anywhere. If an account is compromised,
            # there is no way to investigate when or how it happened.
            # (no logging here)

            # FIX: record every successful login for later auditing.
            AccessLog.objects.create(
                user=user,
                action='login',
                ip_address=ip,
            )

            return redirect('dashboard')

        # FIX for FLAW 3: record this failure in the database so it
        # counts against this IP's limit even without a session cookie.
        LoginAttempt.objects.create(ip_address=ip, username=username or '')

        # FIX for FLAW 4: failed attempts are exactly the event that
        # matters most for brute-force detection, so they get logged
        # too, not just the eventual lockout or a successful login.
        AccessLog.objects.create(
            user=None,
            action='login_failed',
            detail=f'username={username}',
            ip_address=ip,
        )

        return render(request, 'monitoring/login.html', {'error': 'Invalid credentials'})

    return render(request, 'monitoring/login.html')



def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def dashboard_view(request):
    servers = MonitoredServer.objects.filter(owner=request.user)
    return render(request, 'monitoring/dashboard.html', {'servers': servers})

@login_required
def server_detail_view(request, server_id):
    # FLAW 2 (Broken Access Control): ...
    # server = MonitoredServer.objects.get(id=server_id)

    # FIX: ...
    server = get_object_or_404(MonitoredServer, id=server_id, owner=request.user)

    query = request.GET.get('q', '')

    # FLAW 4: viewing a server's logs, or searching within them, is
    # never recorded. There's no audit trail of who looked at what.
    # (no logging here)

    # FIX: log every access and search for auditing purposes.
    AccessLog.objects.create(
        user=request.user,
        action='view_server',
        detail=f'server={server.name} query={query}' if query else f'server={server.name}',
        ip_address=get_client_ip(request),
    )

    if query:
        # FLAW 1 (Injection): ...
        # with connection.cursor() as cursor:
        #     sql = "SELECT id, timestamp, ip_address, username, success FROM monitoring_logentry WHERE server_id = " + str(server.id) + " AND (ip_address LIKE '%" + query + "%' OR username LIKE '%" + query + "%') ORDER BY timestamp DESC"
        #     cursor.execute(sql)
        #     rows = cursor.fetchall()
        #     entries = [
        #         {'id': r[0], 'timestamp': r[1], 'ip_address': r[2], 'username': r[3], 'success': r[4]}
        #         for r in rows
        #     ]

        # FIX: use the Django ORM with parameterized filtering...
        entries = LogEntry.objects.filter(server=server).filter(
            models.Q(ip_address__icontains=query) | models.Q(username__icontains=query)
        ).order_by('-timestamp')
    else:
        entries = LogEntry.objects.filter(server=server).order_by('-timestamp')

    blocked = BlockedIP.objects.filter(server=server)
    return render(request, 'monitoring/server_detail.html', {
        'server': server,
        'entries': entries,
        'blocked': blocked,
        'query': query,
    })

@login_required
def access_log_view(request):
    logs = AccessLog.objects.filter(user=request.user).order_by('-timestamp')[:50]
    return render(request, 'monitoring/access_log.html', {'logs': logs})