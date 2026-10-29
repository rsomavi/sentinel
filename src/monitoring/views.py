from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.db import connection, models
from .models import MonitoredServer, LogEntry, BlockedIP


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
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
    server = MonitoredServer.objects.get(id=server_id, owner=request.user)

    query = request.GET.get('q', '')

    if query:
        # FLAW 1 (Injection): vulnerable raw SQL query built with string
        # concatenation — the user-supplied "query" is inserted directly
        # into the SQL statement, allowing SQL injection.
        # with connection.cursor() as cursor:
        #     sql = "SELECT id, timestamp, ip_address, username, success FROM monitoring_logentry WHERE server_id = " + str(server.id) + " AND (ip_address LIKE '%" + query + "%' OR username LIKE '%" + query + "%') ORDER BY timestamp DESC"
        #     cursor.execute(sql)
        #     rows = cursor.fetchall()
        #     entries = [
        #         {'id': r[0], 'timestamp': r[1], 'ip_address': r[2], 'username': r[3], 'success': r[4]}
        #         for r in rows
        #     ]

        # FIX: use the Django ORM with parameterized filtering instead of
        # raw SQL. The ORM always escapes/parameterizes values, so user
        # input can never alter the structure of the query.
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