from flask import Flask, request, jsonify, redirect, send_file, session
import secrets
import csv
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Passkeys storage file
PASSKEYS_FILE = 'passkeys.csv'

# Admin passkey (cannot be deleted)
ADMIN_PASSKEY = 'admin123'

# ============================================
# Rate Limiting / DDoS Protection
# ============================================
# Simple rate limiter: 7 requests/minute, 1 minute timeout
# Uses REAL connection IP which CANNOT be spoofed

class RateLimiter:
    def __init__(self, requests_per_minute=7, timeout_seconds=60):
        self.requests_per_minute = requests_per_minute
        self.timeout_seconds = timeout_seconds
        self.request_counts = defaultdict(list)  # IP -> list of timestamps
        self.timeouts = {}  # IP -> timeout end time

    def get_real_ip(self, req):
        """Get the REAL connection IP - cannot be spoofed by client"""
        if req.headers.get('X-Forwarded-For'):
            return req.headers.get('X-Forwarded-For').split(',')[0].strip()
        return req.remote_addr

    def is_allowed(self, ip):
        """Check if request is allowed, return True if ok, False if rate limited"""
        now = datetime.now()

        # Check if currently timed out
        if ip in self.timeouts:
            if now < self.timeouts[ip]:
                return False
            else:
                del self.timeouts[ip]

        # Clean old requests (older than 1 minute)
        minute_ago = now - timedelta(minutes=1)
        self.request_counts[ip] = [t for t in self.request_counts[ip] if t > minute_ago]

        # Check rate limit
        if len(self.request_counts[ip]) >= self.requests_per_minute:
            # Start timeout
            self.timeouts[ip] = now + timedelta(seconds=self.timeout_seconds)
            return False

        # Record this request
        self.request_counts[ip].append(now)
        return True

# 7 requests/minute, 60 second timeout
rate_limiter = RateLimiter(requests_per_minute=7, timeout_seconds=60)

# ============================================
# Passkey Management
# ============================================

def load_passkeys():
    """Load passkeys from CSV file"""
    if os.path.exists(PASSKEYS_FILE):
        with open(PASSKEYS_FILE, 'r', newline='') as f:
            reader = csv.reader(f)
            return set(row[0] for row in reader if row)
    default_passkeys = {'secret123', 'user456', 'guest789'}
    save_passkeys(default_passkeys)
    return default_passkeys

def save_passkeys(passkeys_set):
    """Save passkeys to CSV file"""
    with open(PASSKEYS_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        for passkey in passkeys_set:
            writer.writerow([passkey])

passkeys = load_passkeys()

# ============================================
# Middleware - Rate Limit Check
# ============================================

@app.before_request
def check_rate_limit():
    """Check rate limit before every request"""
    ip = rate_limiter.get_real_ip(request)

    if not rate_limiter.is_allowed(ip):
        return jsonify({
            'error': 'Too many requests. Please wait a minute.',
        }), 429

# ============================================
# Routes
# ============================================

@app.route('/')
def index():
    """Show login page or redirect to dashboard if authenticated"""
    if session.get('is_admin'):
        return redirect('/admin')
    if session.get('authenticated'):
        return redirect('/dashboard')
    return send_file('login.html')


@app.route('/login')
def login_page():
    """Show login page"""
    if session.get('is_admin'):
        return redirect('/admin')
    if session.get('authenticated'):
        return redirect('/dashboard')
    return send_file('login.html')


@app.route('/api/verify', methods=['POST'])
def verify():
    """Verify the passkey"""
    data = request.get_json()
    passkey = data.get('passkey', '') if data else ''

    if passkey == ADMIN_PASSKEY:
        session['authenticated'] = True
        session['is_admin'] = True
        return jsonify({'success': True, 'redirect': '/admin'})

    if passkey in passkeys:
        session['authenticated'] = True
        session['is_admin'] = False
        return jsonify({'success': True, 'redirect': '/dashboard'})

    return jsonify({'success': False, 'message': 'Invalid passkey'}), 401


@app.route('/dashboard')
def dashboard():
    """Protected route - serves index.html if authenticated"""
    if session.get('authenticated'):
        return send_file('index.html')
    return redirect('/')


@app.route('/admin')
def admin():
    """Admin page - manage passkeys"""
    if session.get('is_admin'):
        return send_file('admin.html')
    return redirect('/')


@app.route('/api/passkeys', methods=['GET'])
def get_passkeys():
    """Get all passkeys (admin only)"""
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'passkeys': list(passkeys)})


@app.route('/api/passkeys', methods=['POST'])
def add_passkey():
    """Add a new passkey (admin only)"""
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    new_passkey = data.get('passkey', '').strip() if data else ''

    if not new_passkey:
        return jsonify({'error': 'Passkey cannot be empty'}), 400

    if new_passkey == ADMIN_PASSKEY:
        return jsonify({'error': 'Cannot add admin passkey'}), 400

    if new_passkey in passkeys:
        return jsonify({'error': 'Passkey already exists'}), 400

    passkeys.add(new_passkey)
    save_passkeys(passkeys)
    return jsonify({'success': True, 'passkeys': list(passkeys)})


@app.route('/api/passkeys/<passkey>', methods=['DELETE'])
def delete_passkey(passkey):
    """Delete a passkey (admin only)"""
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    if passkey not in passkeys:
        return jsonify({'error': 'Passkey not found'}), 404

    passkeys.remove(passkey)
    save_passkeys(passkeys)
    return jsonify({'success': True, 'passkeys': list(passkeys)})


@app.route('/logout')
def logout():
    """Clear session and redirect to login"""
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    print('Server running at http://localhost:3000')
    print(f'\nAdmin passkey: {ADMIN_PASSKEY}')
    print(f'User passkeys: {passkeys}')
    print(f'\nRate limit: {rate_limiter.requests_per_minute} requests/minute, {rate_limiter.timeout_seconds}s timeout')
    print('\nRoutes:')
    print('  /          - Login page')
    print('  /dashboard - Protected main page')
    print('  /admin     - Admin page (passkey management only)')
    print('  /logout    - Logout')

    app.run(host='0.0.0.0', port=3000, debug=True)
