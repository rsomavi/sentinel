from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
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
    entries = LogEntry.objects.filter(server=server).order_by('-timestamp')
    blocked = BlockedIP.objects.filter(server=server)
    return render(request, 'monitoring/server_detail.html', {
        'server': server,
        'entries': entries,
        'blocked': blocked,
    })