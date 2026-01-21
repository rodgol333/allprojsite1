from flask import Flask, request, jsonify, send_file, send_from_directory, render_template
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__, template_folder='templates')

# Games folder
GAMES_FOLDER = 'games'

# ============================================
# Rate Limiting / DDoS Protection
# ============================================

class RateLimiter:
    def __init__(self, requests_per_minute=30, timeout_seconds=60):
        self.requests_per_minute = requests_per_minute
        self.timeout_seconds = timeout_seconds
        self.request_counts = defaultdict(list)
        self.timeouts = {}

    def get_real_ip(self, req):
        if req.headers.get('X-Forwarded-For'):
            return req.headers.get('X-Forwarded-For').split(',')[0].strip()
        return req.remote_addr

    def is_allowed(self, ip):
        now = datetime.now()

        if ip in self.timeouts:
            if now < self.timeouts[ip]:
                return False
            else:
                del self.timeouts[ip]

        minute_ago = now - timedelta(minutes=1)
        self.request_counts[ip] = [t for t in self.request_counts[ip] if t > minute_ago]

        if len(self.request_counts[ip]) >= self.requests_per_minute:
            self.timeouts[ip] = now + timedelta(seconds=self.timeout_seconds)
            return False

        self.request_counts[ip].append(now)
        return True

# 30 requests/minute, 60 second timeout
rate_limiter = RateLimiter(requests_per_minute=30, timeout_seconds=60)

# ============================================
# Games List
# ============================================

def get_games_list():
    if not os.path.exists(GAMES_FOLDER):
        return []
    games = [name for name in os.listdir(GAMES_FOLDER)
             if os.path.isdir(os.path.join(GAMES_FOLDER, name))]
    return sorted(games)

# ============================================
# Middleware - Rate Limit Check
# ============================================

@app.before_request
def check_rate_limit():
    ip = rate_limiter.get_real_ip(request)

    if not rate_limiter.is_allowed(ip):
        return jsonify({
            'error': 'too many requests',
        }), 429

# ============================================
# Routes
# ============================================

@app.route('/')
def index():
    games = get_games_list()
    return render_template('home.html', games=games)


# ============================================
# Games Routes
# ============================================

@app.route('/<game_name>/')
def serve_game(game_name):
    """Serve a game's index.html"""
    game_path = os.path.join(GAMES_FOLDER, game_name, 'index.html')
    if os.path.exists(game_path):
        return send_file(game_path)
    return "Not found", 404


@app.route('/<game_name>/<path:filename>')
def serve_game_assets(game_name, filename):
    """Serve game assets (js, css, images, etc.)"""
    game_folder = os.path.join(GAMES_FOLDER, game_name)
    if os.path.exists(os.path.join(game_folder, filename)):
        return send_from_directory(game_folder, filename)
    return "File not found", 404


if __name__ == '__main__':
    games = get_games_list()
    print('Server running at http://localhost:3000')
    print(f'Rate limit: {rate_limiter.requests_per_minute} requests/minute, {rate_limiter.timeout_seconds}s timeout')

    app.run(host='0.0.0.0', port=3000, debug=True)
