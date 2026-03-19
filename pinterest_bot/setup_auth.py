"""
Pinterest OAuth Setup - auto-captures redirect via local server.
Run this once to get your access + refresh tokens.
"""

import requests
import json
import base64
import urllib.parse
import webbrowser
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

APP_ID       = '1554290'
APP_SECRET   = 'd8533eba4ce9fc351487eaa80498ce19db376114'
REDIRECT_URI = 'http://localhost:8080'
SCOPES       = 'boards:read,boards:write,pins:read,pins:write'
TOKENS_FILE  = Path(__file__).parent / 'tokens.json'

captured_code = None

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global captured_code
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        captured_code = params.get('code', [None])[0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h2>Auth complete! You can close this tab.</h2>')

    def log_message(self, *args):
        pass  # silence server logs

# Start local server in background
server = HTTPServer(('localhost', 8080), Handler)
thread = threading.Thread(target=server.handle_request)
thread.daemon = True
thread.start()

# Open browser
auth_url = (
    f'https://www.pinterest.com/oauth/'
    f'?client_id={APP_ID}'
    f'&redirect_uri={urllib.parse.quote(REDIRECT_URI)}'
    f'&response_type=code'
    f'&scope={SCOPES}'
    f'&state=pinterestbot'
)
print('Opening Pinterest auth page in browser...')
print('Approve the app, then come back here.')
webbrowser.open(auth_url)

# Wait for the callback
thread.join(timeout=120)

if not captured_code:
    print('No code received within 2 minutes. Try again.')
    exit(1)

print(f'Code captured. Exchanging for tokens...')

credentials = base64.b64encode(f'{APP_ID}:{APP_SECRET}'.encode()).decode()
resp = requests.post(
    'https://api-sandbox.pinterest.com/v5/oauth/token',
    headers={
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    data={
        'grant_type': 'authorization_code',
        'code': captured_code,
        'redirect_uri': REDIRECT_URI,
    }
)

if resp.status_code != 200:
    print(f'Token exchange failed: {resp.text}')
    exit(1)

tokens = resp.json()
TOKENS_FILE.write_text(json.dumps(tokens, indent=2))
print(f'Tokens saved to {TOKENS_FILE}')
print('Setup complete! Run bot.py to post the first pin.')
