from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.db import connection, models
from .models import MonitoredServer, LogEntry, BlockedIP, AccessLog


import time

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

    # FIX: track failed attempts in the session and lock out the user
    # temporarily after too many consecutive failures, mitigating
    # brute-force attacks against the login form.
    locked_until = request.session.get('login_locked_until')
    if locked_until and time.time() < locked_until:
        remaining = int(locked_until - time.time())
        return render(request, 'monitoring/login.html', {
            'error': f'Too many failed attempts. Try again in {remaining} seconds.'
        })

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            request.session['login_attempts'] = 0
            login(request, user)

            # FLAW 4 (Security Logging Failures): successful logins are
            # never recorded anywhere. If an account is compromised,
            # there is no way to investigate when or how it happened.
            # (no logging here)

            # FIX: record every successful login for later auditing.
            AccessLog.objects.create(
                user=user,
                action='login',
                ip_address=get_client_ip(request),
            )

            return redirect('dashboard')

        attempts = request.session.get('login_attempts', 0) + 1
        request.session['login_attempts'] = attempts

        if attempts >= LOGIN_ATTEMPTS_THRESHOLD:
            request.session['login_locked_until'] = time.time() + LOGIN_LOCKOUT_SECONDS
            request.session['login_attempts'] = 0
            return render(request, 'monitoring/login.html', {
                'error': f'Too many failed attempts. Try again in {LOGIN_LOCKOUT_SECONDS} seconds.'
            })

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