"""
Print3DBuddy Pinterest Bot
Automatically creates pins linking to print3dbuddy.com articles and tools.
Run manually or schedule with Task Scheduler / cron.
"""

import requests
import json
import time
import random
from datetime import datetime
from pathlib import Path

# ── Credentials ───────────────────────────────────────────────────────────────

APP_ID     = '1554290'
APP_SECRET = 'd8533eba4ce9fc351487eaa80498ce19db376114'

TOKENS_FILE = Path(__file__).parent / 'tokens.json'

# ── Token management ──────────────────────────────────────────────────────────

def load_tokens():
    if TOKENS_FILE.exists():
        return json.loads(TOKENS_FILE.read_text())
    return {}

def save_tokens(tokens):
    TOKENS_FILE.write_text(json.dumps(tokens, indent=2))

def refresh_access_token(refresh_token):
    import base64
    credentials = base64.b64encode(f'{APP_ID}:{APP_SECRET}'.encode()).decode()
    resp = requests.post('https://api-sandbox.pinterest.com/v5/oauth/token',
        headers={
            'Authorization': f'Basic {credentials}',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
    )
    if resp.status_code == 200:
        return resp.json()
    raise Exception(f'Token refresh failed: {resp.text}')

def get_access_token():
    tokens = load_tokens()
    if not tokens:
        raise Exception('No tokens found. Run setup first.')
    # Refresh if needed (tokens last 30 days, refresh every run to be safe)
    try:
        new_tokens = refresh_access_token(tokens['refresh_token'])
        tokens.update(new_tokens)
        save_tokens(tokens)
        return tokens['access_token']
    except Exception:
        return tokens['access_token']

# ── Pinterest API ─────────────────────────────────────────────────────────────

BASE_URL = 'https://api-sandbox.pinterest.com/v5'

def get_boards(access_token):
    resp = requests.get(f'{BASE_URL}/boards',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    return resp.json()

def create_board(access_token, name):
    resp = requests.post(f'{BASE_URL}/boards',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        },
        json={'name': name, 'privacy': 'PUBLIC'}
    )
    return resp.status_code, resp.json()

def create_pin(access_token, board_id, title, description, link, image_url):
    payload = {
        'board_id': board_id,
        'title': title,
        'description': description,
        'link': link,
        'media_source': {
            'source_type': 'image_url',
            'url': image_url,
        }
    }
    resp = requests.post(f'{BASE_URL}/pins',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        },
        json=payload
    )
    return resp.status_code, resp.json()

# ── Pin content ───────────────────────────────────────────────────────────────

PINS = [
    {
        'title': 'How to calibrate your 3D printer (step by step)',
        'description': 'New to 3D printing? Calibration is the single most important thing you can do for print quality. This guide covers bed levelling, Z offset, E-steps, flow rate, and retraction - in the right order. Free guide at Print3DBuddy.',
        'link': 'https://print3dbuddy.com/posts/how-to-calibrate-your-first-3d-printer/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'PLA vs PETG vs ABS - which filament should you use?',
        'description': 'Not sure which filament to buy? PLA, PETG, and ABS all have different strengths, weaknesses, and print requirements. This plain-English comparison helps beginners pick the right one for their project.',
        'link': 'https://print3dbuddy.com/posts/pla-vs-petg-vs-abs-which-filament-for-beginners/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'How to fix 3D printer stringing (fast)',
        'description': 'Stringy prints are one of the most common 3D printing problems. The fix is usually retraction settings, temperature, or travel speed. This guide walks you through each one.',
        'link': 'https://print3dbuddy.com/posts/how-to-fix-3d-printer-stringing/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'Best free 3D printing tools for beginners',
        'description': 'Stop guessing your print settings. These free tools calculate filament cost, give you the right settings for any material, recommend the best slicer for your printer, and estimate filament usage from your STL file.',
        'link': 'https://tools.print3dbuddy.com',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'How to stop 3D prints warping (beginner guide)',
        'description': 'Warping ruins prints and wastes filament. The causes are usually bed adhesion, cooling, or enclosure issues. This guide covers every fix - brims, bed surfaces, temperature, and material-specific tips.',
        'link': 'https://print3dbuddy.com/posts/how-to-fix-3d-print-warping/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'What does 3D printing infill actually do?',
        'description': 'Infill percentage affects strength, weight, and print time more than most beginners realise. This guide explains every infill pattern, when to use each one, and how to balance strength vs speed.',
        'link': 'https://print3dbuddy.com/posts/3d-printing-infill-patterns-guide/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'How to reduce 3D print time without losing quality',
        'description': 'Most prints can be cut by 30-40% with two setting changes. Layer height and print speed are where the time goes. This guide shows you exactly what to change and what to leave alone.',
        'link': 'https://print3dbuddy.com/posts/how-to-reduce-3d-print-time/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'Best 3D printers for beginners in 2025',
        'description': 'Bambu Lab A1 Mini, Creality Ender 3 V3 SE, or Prusa MK4? An honest comparison of the best beginner 3D printers in 2025 - what each one is actually like to use day to day.',
        'link': 'https://print3dbuddy.com/posts/best-3d-printers-for-beginners-2025/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'TPU flexible filament - beginner guide',
        'description': 'TPU is one of the most useful filaments you can print - phone cases, gaskets, grips, wheels. But it jams easily if you get the settings wrong. This guide covers everything you need to print TPU successfully.',
        'link': 'https://print3dbuddy.com/posts/tpu-flexible-filament-beginners-guide/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'How to store filament properly (avoid moisture damage)',
        'description': 'Wet filament causes stringing, bubbling, poor layer adhesion, and jams. PLA, PETG, and Nylon absorb moisture at different rates. This guide covers storage, desiccant, and how to dry filament that\'s already wet.',
        'link': 'https://print3dbuddy.com/posts/how-to-store-filament-properly/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'Calculate exactly what your 3D prints cost',
        'description': 'Most people have no idea what their prints actually cost. This free filament cost calculator works it out instantly - filament, electricity, and waste included. Free to use at Print3DBuddy.',
        'link': 'https://tools.print3dbuddy.com',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
    {
        'title': 'Best 3D printer upgrades under $50',
        'description': 'The best upgrades aren\'t always expensive. A PEI sheet, Capricorn tube, or BLTouch can transform a budget printer. This guide ranks the best upgrades by actual impact on print quality.',
        'link': 'https://print3dbuddy.com/posts/best-3d-printer-upgrades-under-50/',
        'image_url': 'https://images.unsplash.com/photo-1612815154858-60aa4c59eaa6?w=1000&q=80',
    },
]

# ── Posted pins log ───────────────────────────────────────────────────────────

LOG_FILE = Path(__file__).parent / 'posted_pins.json'

def load_posted():
    if LOG_FILE.exists():
        return json.loads(LOG_FILE.read_text())
    return []

def save_posted(posted):
    LOG_FILE.write_text(json.dumps(posted, indent=2))

# ── Main ──────────────────────────────────────────────────────────────────────

def post_next_pin():
    access_token = get_access_token()

    # Sandbox board ID (boards list endpoint is buggy in sandbox)
    board_id = '1092615628287631321'
    board_name = '3D Printing Guide 2025'
    print(f'Posting to board: {board_name} ({board_id})')

    # Find next unposted pin
    posted = load_posted()
    posted_links = [p['link'] for p in posted]

    unposted = [p for p in PINS if p['link'] not in posted_links]
    if not unposted:
        print('All pins have been posted. Add more to PINS list.')
        return

    pin = unposted[0]
    print(f'Creating pin: {pin["title"]}')

    status, response = create_pin(
        access_token,
        board_id,
        pin['title'],
        pin['description'],
        pin['link'],
        pin['image_url']
    )

    if status == 201:
        posted.append({
            'link': pin['link'],
            'title': pin['title'],
            'pin_id': response.get('id'),
            'posted_at': datetime.now().isoformat(),
        })
        save_posted(posted)
        print(f'Success! Pin ID: {response.get("id")}')
        print(f'{len(unposted) - 1} pins remaining.')
    else:
        print(f'Failed ({status}): {response}')


if __name__ == '__main__':
    post_next_pin()
