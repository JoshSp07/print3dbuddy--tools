"""
Print3DBuddy Tools - Flask web app
Tools: Filament Cost Calculator, Print Settings Cheat Sheet,
       Slicer Recommender, STL Filament Estimator
Free tier: 3 uses. Paid tier: £5 one-time OR £2/month via Stripe.
"""

import os
import io
import struct
import sqlite3
import numpy as np
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
import stripe

DATABASE_URL = os.environ.get('DATABASE_URL', '')
USE_POSTGRES = bool(DATABASE_URL)
if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max upload

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PRICE_MONTHLY   = os.environ.get('STRIPE_PRICE_MONTHLY', '')    # £2/month
STRIPE_PRICE_LIFETIME  = os.environ.get('STRIPE_PRICE_LIFETIME', '')   # £5 one-time
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
DOMAIN = os.environ.get('DOMAIN', 'http://localhost:5000')

FREE_USES = 3
DB_PATH = 'users.db'

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        if USE_POSTGRES:
            url = DATABASE_URL
            if url.startswith('postgres://'):
                url = url.replace('postgres://', 'postgresql://', 1)
            g.db = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def db_execute(sql, params=()):
    """Execute a query, handling placeholder differences between SQLite and PostgreSQL."""
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor()
        cur.execute(sql, params)
        db.commit()
        return cur
    else:
        return db.execute(sql.replace('%s', '?'), params)

def db_fetchone(sql, params=()):
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor()
        cur.execute(sql, params)
        return cur.fetchone()
    else:
        return db.execute(sql.replace('%s', '?'), params).fetchone()

def db_fetchall(sql, params=()):
    db = get_db()
    if USE_POSTGRES:
        cur = db.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    else:
        return db.execute(sql.replace('%s', '?'), params).fetchall()

def db_commit():
    if not USE_POSTGRES:
        get_db().commit()

def init_db():
    if USE_POSTGRES:
        url = DATABASE_URL
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        conn = psycopg2.connect(url)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            uses_remaining INTEGER DEFAULT 3,
            is_paid INTEGER DEFAULT 0,
            payment_type TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    else:
        db = sqlite3.connect(DB_PATH)
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            uses_remaining INTEGER DEFAULT 3,
            is_paid INTEGER DEFAULT 0,
            payment_type TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        try:
            db.execute('ALTER TABLE users ADD COLUMN payment_type TEXT DEFAULT "free"')
        except Exception:
            pass
        db.commit()
        db.close()

# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to use the tools.', 'info')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    return db_fetchone('SELECT * FROM users WHERE id = %s', (session['user_id'],))

def can_use_tool(user):
    return bool(user['is_paid']) or user['uses_remaining'] > 0

def consume_use(user_id):
    db_execute('UPDATE users SET uses_remaining = uses_remaining - 1 WHERE id = %s AND uses_remaining > 0 AND is_paid = 0', (user_id,))
    db_commit()

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
        if db_fetchone('SELECT id FROM users WHERE email = %s', (email,)):
            flash('An account with that email already exists.', 'error')
            return render_template('register.html')
        db_execute('INSERT INTO users (email, password_hash) VALUES (%s, %s)',
                   (email, generate_password_hash(password)))
        db_commit()
        user = db_fetchone('SELECT * FROM users WHERE email = %s', (email,))
        session['user_id'] = user['id']
        flash(f'Welcome! You have {FREE_USES} free uses across all tools.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = db_fetchone('SELECT * FROM users WHERE email = %s', (email,))
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Incorrect email or password.', 'error')
            return render_template('login.html')
        session['user_id'] = user['id']
        return redirect(request.args.get('next', url_for('dashboard')))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ── Main routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', user=get_current_user())

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=get_current_user())

# ── Tool data ─────────────────────────────────────────────────────────────────

SETTINGS_DB = {
    'PLA': {
        'nozzle_temp': '195-215°C', 'bed_temp': '55-65°C',
        'print_speed': '50-80mm/s', 'first_layer_speed': '20-25mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-7mm at 45mm/s',
        'cooling': '50-100%', 'enclosure': 'Not required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI, glass, or BuildTak',
        'notes': 'Most forgiving material. Great starting point. Avoid enclosures above 30C ambient.',
    },
    'PLA+': {
        'nozzle_temp': '200-230°C', 'bed_temp': '55-65°C',
        'print_speed': '50-80mm/s', 'first_layer_speed': '20-25mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-7mm at 45mm/s',
        'cooling': '50-100%', 'enclosure': 'Not required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI, glass, or BuildTak',
        'notes': 'Tougher and less brittle than standard PLA. May need slightly higher temp. Store dry.',
    },
    'Silk PLA': {
        'nozzle_temp': '210-230°C', 'bed_temp': '55-65°C',
        'print_speed': '30-50mm/s', 'first_layer_speed': '20mm/s',
        'retraction_direct': '2-4mm at 25mm/s', 'retraction_bowden': '5-7mm at 45mm/s',
        'cooling': '50-80%', 'enclosure': 'Not required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI or glass',
        'notes': 'Print slower than standard PLA for best surface finish. Tends to string more - tune retraction carefully.',
    },
    'PETG': {
        'nozzle_temp': '230-250°C', 'bed_temp': '70-85°C',
        'print_speed': '40-60mm/s', 'first_layer_speed': '20-25mm/s',
        'retraction_direct': '0.5-2mm at 25mm/s', 'retraction_bowden': '3-6mm at 40mm/s',
        'cooling': '20-40%', 'enclosure': 'Not required (helpful)',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI textured (avoid smooth glass - sticks too hard)',
        'notes': 'Strings more than PLA. Reduce retraction if getting jams. Adhesive to smooth surfaces - use release agent on glass.',
    },
    'PETG-CF': {
        'nozzle_temp': '240-260°C', 'bed_temp': '70-85°C',
        'print_speed': '30-50mm/s', 'first_layer_speed': '20mm/s',
        'retraction_direct': '0.5-2mm at 25mm/s', 'retraction_bowden': '3-5mm at 40mm/s',
        'cooling': '20-40%', 'enclosure': 'Not required (helpful)',
        'hardened_nozzle': 'Required', 'bed_surface': 'PEI textured',
        'notes': 'Carbon fibre particles destroy brass nozzles - hardened steel required. Stiffer and stronger than standard PETG.',
    },
    'ABS': {
        'nozzle_temp': '230-250°C', 'bed_temp': '100-110°C',
        'print_speed': '40-60mm/s', 'first_layer_speed': '20-25mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-7mm at 40mm/s',
        'cooling': '0-10%', 'enclosure': 'Required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI or garolite',
        'notes': 'Warps badly without enclosure. Emits styrene fumes - ventilate well. Add brim for large prints.',
    },
    'ASA': {
        'nozzle_temp': '235-255°C', 'bed_temp': '100-110°C',
        'print_speed': '40-60mm/s', 'first_layer_speed': '20-25mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-7mm at 40mm/s',
        'cooling': '0-15%', 'enclosure': 'Required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI textured',
        'notes': 'Better UV resistance than ABS. Slightly less prone to warping. Good for outdoor parts. Similar print requirements to ABS.',
    },
    'TPU 95A': {
        'nozzle_temp': '220-235°C', 'bed_temp': '30-60°C',
        'print_speed': '20-30mm/s', 'first_layer_speed': '15-20mm/s',
        'retraction_direct': '0-2mm at 20mm/s', 'retraction_bowden': '0-1mm (minimal)',
        'cooling': '30-50%', 'enclosure': 'Not required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI, glass, or BuildTak',
        'notes': 'Print SLOW - speed is the top cause of TPU jams. Direct drive strongly preferred. Minimal retraction. Keep bone dry.',
    },
    'TPU 85A (Soft)': {
        'nozzle_temp': '215-230°C', 'bed_temp': '30-50°C',
        'print_speed': '15-25mm/s', 'first_layer_speed': '10-15mm/s',
        'retraction_direct': '0mm (disabled)', 'retraction_bowden': 'Not recommended',
        'cooling': '20-40%', 'enclosure': 'Not required',
        'hardened_nozzle': 'No', 'bed_surface': 'PEI or BuildTak',
        'notes': 'Very soft - needs direct drive. Disable retraction entirely. Extremely slow. Bowden printers will likely jam.',
    },
    'Nylon (PA6/PA12)': {
        'nozzle_temp': '240-270°C', 'bed_temp': '70-90°C',
        'print_speed': '30-50mm/s', 'first_layer_speed': '20mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-7mm at 40mm/s',
        'cooling': '0-20%', 'enclosure': 'Recommended',
        'hardened_nozzle': 'No (required for CF variants)', 'bed_surface': 'Garolite / FR4',
        'notes': 'Extremely hygroscopic - must be bone dry. Use garolite bed for best adhesion. Strong and flexible when printed well.',
    },
    'Nylon CF': {
        'nozzle_temp': '250-280°C', 'bed_temp': '80-100°C',
        'print_speed': '25-45mm/s', 'first_layer_speed': '15-20mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-6mm at 40mm/s',
        'cooling': '0-20%', 'enclosure': 'Required',
        'hardened_nozzle': 'Required', 'bed_surface': 'Garolite / FR4',
        'notes': 'Hardened steel nozzle required - CF destroys brass fast. Extremely strong and stiff. Requires careful moisture control.',
    },
    'PC (Polycarbonate)': {
        'nozzle_temp': '260-310°C', 'bed_temp': '110-120°C',
        'print_speed': '25-40mm/s', 'first_layer_speed': '15-20mm/s',
        'retraction_direct': '1-3mm at 25mm/s', 'retraction_bowden': '4-6mm at 40mm/s',
        'cooling': '0-10%', 'enclosure': 'Required',
        'hardened_nozzle': 'Recommended', 'bed_surface': 'PEI or Kapton tape',
        'notes': 'Highest heat resistance of common filaments. Requires all-metal hotend (no PTFE at these temps). Very challenging to print.',
    },
    'Wood PLA': {
        'nozzle_temp': '190-220°C', 'bed_temp': '55-65°C',
        'print_speed': '30-50mm/s', 'first_layer_speed': '20mm/s',
        'retraction_direct': '2-4mm at 25mm/s', 'retraction_bowden': '5-7mm at 45mm/s',
        'cooling': '50-100%', 'enclosure': 'Not required',
        'hardened_nozzle': 'Recommended', 'bed_surface': 'PEI or glass',
        'notes': 'Wood particles can clog standard brass nozzles over time. Use 0.4mm or larger. Vary temp for different wood tones.',
    },
    'Glow in the Dark PLA': {
        'nozzle_temp': '200-220°C', 'bed_temp': '55-65°C',
        'print_speed': '30-50mm/s', 'first_layer_speed': '20mm/s',
        'retraction_direct': '2-4mm at 25mm/s', 'retraction_bowden': '5-7mm at 45mm/s',
        'cooling': '50-100%', 'enclosure': 'Not required',
        'hardened_nozzle': 'Required', 'bed_surface': 'PEI or glass',
        'notes': 'Strontium aluminate particles are highly abrasive - destroys brass nozzles quickly. Hardened steel essential.',
    },
}

MATERIAL_DENSITIES = {
    'PLA': 1.24, 'PLA+': 1.24, 'Silk PLA': 1.24, 'Wood PLA': 1.28,
    'Glow in the Dark PLA': 1.40,
    'PETG': 1.27, 'PETG-CF': 1.30,
    'ABS': 1.04, 'ASA': 1.07,
    'TPU 95A': 1.21, 'TPU 85A': 1.18,
    'Nylon (PA6)': 1.14, 'Nylon CF': 1.20,
    'PC': 1.20,
}

# ── Tool 1: Filament Cost Calculator ─────────────────────────────────────────

@app.route('/tools/filament-cost', methods=['GET', 'POST'])
@login_required
def filament_cost():
    user = get_current_user()
    result = None
    if request.method == 'POST':
        if not can_use_tool(user):
            flash('You have used all your free uses. Upgrade to continue.', 'warning')
            return redirect(url_for('upgrade'))
        try:
            spool_price    = float(request.form['spool_price'])
            spool_weight   = float(request.form['spool_weight'])
            print_weight   = float(request.form['print_weight'])
            electricity    = float(request.form.get('electricity_kwh', 0.29))
            print_hours    = float(request.form.get('print_hours', 0))
            waste_pct      = float(request.form.get('waste_pct', 5))

            cost_per_gram    = spool_price / spool_weight
            filament_cost    = cost_per_gram * print_weight
            waste_cost       = filament_cost * (waste_pct / 100)
            electricity_cost = electricity * 0.2 * print_hours
            total_cost       = filament_cost + waste_cost + electricity_cost

            result = {
                'filament_cost':    round(filament_cost, 2),
                'waste_cost':       round(waste_cost, 2),
                'electricity_cost': round(electricity_cost, 2),
                'total_cost':       round(total_cost, 2),
                'cost_per_gram':    round(cost_per_gram, 4),
                'print_weight':     print_weight,
                'prints_per_spool': int(spool_weight / print_weight) if print_weight > 0 else 0,
            }
            if not user['is_paid']:
                consume_use(user['id'])
                user = get_current_user()
        except (ValueError, ZeroDivisionError):
            flash('Please enter valid numbers in all fields.', 'error')
    return render_template('tools/filament_cost.html', user=user, result=result)

# ── Tool 2: Print Settings Cheat Sheet ───────────────────────────────────────

@app.route('/tools/print-settings', methods=['GET', 'POST'])
@login_required
def print_settings():
    user = get_current_user()
    result = None
    selected_material = None
    if request.method == 'POST':
        if not can_use_tool(user):
            flash('You have used all your free uses. Upgrade to continue.', 'warning')
            return redirect(url_for('upgrade'))
        selected_material = request.form.get('material')
        extruder_type     = request.form.get('extruder', 'direct')
        nozzle_size       = request.form.get('nozzle', '0.4mm')
        if selected_material in SETTINGS_DB:
            s = SETTINGS_DB[selected_material]
            retraction = s['retraction_direct'] if extruder_type == 'direct' else s['retraction_bowden']
            result = dict(s)
            result.update({
                'material': selected_material,
                'extruder': extruder_type,
                'retraction': retraction,
                'nozzle': nozzle_size,
            })
            if not user['is_paid']:
                consume_use(user['id'])
                user = get_current_user()
        else:
            flash('Please select a valid material.', 'error')
    return render_template('tools/print_settings.html', user=user, result=result,
                           materials=list(SETTINGS_DB.keys()),
                           selected_material=selected_material)

# ── Tool 3: Slicer Recommender ────────────────────────────────────────────────

@app.route('/tools/slicer-recommender', methods=['GET', 'POST'])
@login_required
def slicer_recommender():
    user = get_current_user()
    result = None
    if request.method == 'POST':
        if not can_use_tool(user):
            flash('You have used all your free uses. Upgrade to continue.', 'warning')
            return redirect(url_for('upgrade'))

        printer_brand = request.form.get('printer_brand')
        experience    = request.form.get('experience')
        priority      = request.form.get('priority')
        materials     = request.form.getlist('materials')
        use_case      = request.form.get('use_case')

        recs = []

        if printer_brand == 'bambu':
            recs.append({'name':'Bambu Studio','verdict':'Best choice',
                'reason':'Built specifically for Bambu printers. One-click printing with optimised profiles. Fastest slicing available. Best default supports.',
                'url':'https://bambulab.com/en/software'})
            recs.append({'name':'OrcaSlicer','verdict':'Power user alternative',
                'reason':'Open-source Bambu Studio fork with advanced calibration tools (flow rate, PA, resonance). Popular with experienced Bambu users.',
                'url':'https://github.com/SoftFever/OrcaSlicer/releases'})

        elif printer_brand == 'prusa':
            recs.append({'name':'PrusaSlicer','verdict':'Best choice',
                'reason':'Made by Prusa specifically for their printers. Best profiles, most reliable results, excellent documentation.',
                'url':'https://www.prusa3d.com/page/prusaslicer_424/'})
            recs.append({'name':'OrcaSlicer','verdict':'Also worth trying',
                'reason':'Strong Prusa profiles and better calibration tools than PrusaSlicer. Good for users who want more control.',
                'url':'https://github.com/SoftFever/OrcaSlicer/releases'})

        elif printer_brand in ('creality', 'elegoo', 'anycubic', 'artillery', 'other'):
            if experience == 'beginner' or priority == 'ease':
                recs.append({'name':'Bambu Studio','verdict':'Best for beginners',
                    'reason':'Cleanest UI, fastest slicing, excellent automatic support generation. Works with any printer - just import your printer profile.',
                    'url':'https://bambulab.com/en/software'})
                recs.append({'name':'Cura','verdict':'Most tutorials available',
                    'reason':'Largest community and tutorial library. If you follow YouTube guides, they probably use Cura.',
                    'url':'https://ultimaker.com/software/ultimaker-cura/'})
            else:
                recs.append({'name':'PrusaSlicer','verdict':'Best for control',
                    'reason':'Full parameter access, variable layer heights, excellent docs. The community standard for non-Bambu/non-Prusa printers.',
                    'url':'https://www.prusa3d.com/page/prusaslicer_424/'})
                recs.append({'name':'OrcaSlicer','verdict':'Best calibration tools',
                    'reason':'Advanced built-in calibration prints for flow rate, pressure advance, and resonance compensation. Great for tuning a new printer.',
                    'url':'https://github.com/SoftFever/OrcaSlicer/releases'})

        elif printer_brand == 'voron':
            recs.append({'name':'OrcaSlicer','verdict':'Best choice',
                'reason':'Best Klipper integration, pressure advance calibration built in, strong Voron community profiles.',
                'url':'https://github.com/SoftFever/OrcaSlicer/releases'})
            recs.append({'name':'SuperSlicer','verdict':'Alternative',
                'reason':'PrusaSlicer fork with many additional calibration features. Large Voron community base.',
                'url':'https://github.com/supermerill/SuperSlicer/releases'})

        # Add material-specific notes
        notes = []
        if 'nylon' in [m.lower() for m in materials] or 'pc' in [m.lower() for m in materials]:
            notes.append('For Nylon/PC: OrcaSlicer or PrusaSlicer have the best exotic material support.')
        if use_case == 'miniatures':
            notes.append('For miniatures: Use 0.2mm or smaller layer height. PrusaSlicer variable layer height is excellent for this.')
        if use_case == 'functional':
            notes.append('For functional parts: OrcaSlicer calibration tools help maximise strength.')

        result = {
            'recommendations': recs,
            'notes': notes,
            'printer_brand': printer_brand,
            'experience': experience,
            'priority': priority,
        }
        if not user['is_paid']:
            consume_use(user['id'])
            user = get_current_user()

    return render_template('tools/slicer_recommender.html', user=user, result=result)

# ── Tool 4: STL Filament Estimator ───────────────────────────────────────────

def parse_stl_volume_cm3(file_bytes):
    """
    Calculate mesh volume in cm³ from STL file bytes (binary or ASCII).
    Uses the divergence theorem (signed tetrahedra method).
    """
    data = file_bytes

    # Try binary STL first
    # Binary STL: 80 byte header, 4 byte triangle count, then 50 bytes per triangle
    if len(data) >= 84:
        try:
            num_triangles = struct.unpack_from('<I', data, 80)[0]
            expected_size = 84 + num_triangles * 50
            if abs(len(data) - expected_size) <= 2:  # binary STL
                triangles = np.frombuffer(data[84:84 + num_triangles * 50],
                                           dtype=np.dtype([
                                               ('normal', '<3f4'),
                                               ('v0', '<3f4'),
                                               ('v1', '<3f4'),
                                               ('v2', '<3f4'),
                                               ('attr', '<u2')
                                           ]))
                v0 = triangles['v0'].astype(np.float64)
                v1 = triangles['v1'].astype(np.float64)
                v2 = triangles['v2'].astype(np.float64)
                # Signed volume of each tetrahedron
                cross = np.cross(v1, v2)
                vol = np.sum(v0 * cross) / 6.0
                volume_mm3 = abs(vol)
                return volume_mm3 / 1000.0  # mm³ -> cm³
        except Exception:
            pass

    # Try ASCII STL
    try:
        text = data.decode('utf-8', errors='ignore')
        vertices = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('vertex'):
                parts = line.split()
                vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
        if len(vertices) >= 3 and len(vertices) % 3 == 0:
            verts = np.array(vertices, dtype=np.float64)
            v0 = verts[0::3]
            v1 = verts[1::3]
            v2 = verts[2::3]
            cross = np.cross(v1, v2)
            vol = np.sum(v0 * cross) / 6.0
            volume_mm3 = abs(vol)
            return volume_mm3 / 1000.0
    except Exception:
        pass

    return None


@app.route('/tools/stl-estimator', methods=['GET', 'POST'])
@login_required
def stl_estimator():
    user = get_current_user()
    result = None

    if request.method == 'POST':
        if not can_use_tool(user):
            flash('You have used all your free uses. Upgrade to continue.', 'warning')
            return redirect(url_for('upgrade'))

        stl_file = request.files.get('stl_file')
        if not stl_file or stl_file.filename == '':
            flash('Please select an STL file.', 'error')
            return render_template('tools/stl_estimator.html', user=user, result=None,
                                   densities=MATERIAL_DENSITIES)

        try:
            file_bytes = stl_file.read()
            volume_cm3 = parse_stl_volume_cm3(file_bytes)

            if volume_cm3 is None or volume_cm3 <= 0:
                flash('Could not read that STL file. Make sure it is a valid binary or ASCII STL.', 'error')
                return render_template('tools/stl_estimator.html', user=user, result=None,
                                       densities=MATERIAL_DENSITIES)

            # User inputs
            infill_pct      = float(request.form.get('infill', 20)) / 100
            num_walls       = int(request.form.get('walls', 3))
            top_bottom      = int(request.form.get('top_bottom', 4))
            layer_height    = float(request.form.get('layer_height', 0.2))
            nozzle_dia      = float(request.form.get('nozzle_dia', 0.4))
            material        = request.form.get('material', 'PLA')
            spool_price     = float(request.form.get('spool_price', 0))
            spool_weight_g  = float(request.form.get('spool_weight', 1000))
            scale_pct       = float(request.form.get('scale', 100)) / 100
            num_copies      = int(request.form.get('copies', 1))

            # Apply scale (volume scales cubically)
            scaled_volume_cm3 = volume_cm3 * (scale_pct ** 3)

            # Estimate surface area from volume (sphere approximation for shell calc)
            # Better: use actual surface area if we have it, else approximate
            surface_area_cm2 = (36 * np.pi * scaled_volume_cm3 ** 2) ** (1/3)

            # Shell volume estimate
            wall_thickness_cm   = num_walls * nozzle_dia * 0.1       # mm -> cm
            tb_thickness_cm     = top_bottom * layer_height * 0.1
            shell_volume_cm3    = surface_area_cm2 * wall_thickness_cm
            shell_volume_cm3   += surface_area_cm2 * tb_thickness_cm * 0.5  # approx top+bottom

            shell_volume_cm3    = min(shell_volume_cm3, scaled_volume_cm3 * 0.9)  # cap at 90%

            # Printed volume
            interior_volume_cm3 = max(scaled_volume_cm3 - shell_volume_cm3, 0)
            printed_volume_cm3  = shell_volume_cm3 + interior_volume_cm3 * infill_pct

            # Material density
            density = MATERIAL_DENSITIES.get(material, 1.24)
            weight_g = printed_volume_cm3 * density * num_copies

            # Filament length (1.75mm diameter filament)
            filament_radius_cm  = 0.1750 / 2 / 10  # 1.75mm -> cm radius
            filament_length_cm  = printed_volume_cm3 / (np.pi * filament_radius_cm ** 2)
            filament_length_m   = filament_length_cm / 100 * num_copies

            # Cost
            cost = 0.0
            if spool_price > 0 and spool_weight_g > 0:
                cost = (weight_g / spool_weight_g) * spool_price

            result = {
                'model_volume_cm3':  round(scaled_volume_cm3, 2),
                'printed_volume_cm3': round(printed_volume_cm3 * num_copies, 2),
                'weight_g':          round(weight_g, 1),
                'filament_length_m': round(filament_length_m, 1),
                'cost':              round(cost, 2),
                'material':          material,
                'infill_pct':        int(infill_pct * 100),
                'num_walls':         num_walls,
                'layer_height':      layer_height,
                'scale_pct':         int(scale_pct * 100),
                'num_copies':        num_copies,
                'filename':          stl_file.filename,
            }
            if not user['is_paid']:
                consume_use(user['id'])
                user = get_current_user()

        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')

    return render_template('tools/stl_estimator.html', user=user, result=result,
                           densities=MATERIAL_DENSITIES)

# ── Stripe ────────────────────────────────────────────────────────────────────

@app.route('/upgrade')
@login_required
def upgrade():
    return render_template('upgrade.html', user=get_current_user(),
                           stripe_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    user = get_current_user()
    plan = request.form.get('plan', 'monthly')  # 'monthly' or 'lifetime'

    if not stripe.api_key:
        flash('Payment system not yet configured. Check back soon.', 'info')
        return redirect(url_for('upgrade'))

    price_id = STRIPE_PRICE_MONTHLY if plan == 'monthly' else STRIPE_PRICE_LIFETIME
    if not price_id:
        flash('Payment system not yet configured. Check back soon.', 'info')
        return redirect(url_for('upgrade'))

    try:
        mode = 'subscription' if plan == 'monthly' else 'payment'
        checkout = stripe.checkout.Session.create(
            payment_method_types=['card'],
            mode=mode,
            customer_email=user['email'],
            line_items=[{'price': price_id, 'quantity': 1}],
            success_url=DOMAIN + '/payment-success?session_id={CHECKOUT_SESSION_ID}&plan=' + plan,
            cancel_url=DOMAIN + '/upgrade',
            metadata={'user_id': str(user['id']), 'plan': plan},
        )
        return redirect(checkout.url)
    except Exception as e:
        flash('Could not start checkout. Please try again.', 'error')
        return redirect(url_for('upgrade'))

@app.route('/payment-success')
@login_required
def payment_success():
    plan = request.args.get('plan', 'monthly')
    db_execute('UPDATE users SET is_paid=1, payment_type=%s WHERE id=%s',
               (plan, session['user_id']))
    db_commit()
    flash('Payment successful! You now have unlimited access.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return '', 400
    if event['type'] == 'customer.subscription.deleted':
        customer_id = event['data']['object']['customer']
        db_execute("UPDATE users SET is_paid=0, payment_type='free' WHERE stripe_customer_id=%s",
                   (customer_id,))
        db_commit()
    return '', 200


# ── Test Prints ───────────────────────────────────────────────────────────────

TEST_PRINTS = [
    {
        'id': 'overhang-test',
        'title': 'Overhang Test',
        'tagline': 'Find your printer\'s maximum overhang angle',
        'tag': 'Overhang',
        'summary': 'Prints 11 fins angled from 20\u00b0 to 70\u00b0 so you can see exactly where your printer starts to struggle with overhangs. Print it once without supports, check which fins look clean, and you\'ll know the precise angle at which to set your slicer\'s support threshold \u2014 no more guessing.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>11 fins side by side, each angled further from vertical \u2014 20\u00b0 (nearly upright) to 70\u00b0 (nearly horizontal). Most printers handle up to 45\u201350\u00b0 cleanly.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">How to run it</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Print at your normal settings with no supports enabled.</li>
  <li>Look at the underside of each fin straight on.</li>
  <li>Find the first fin where the surface looks rough, droopy, or stringy.</li>
  <li>The previous fin's angle is your safe overhang limit.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">What to do with the result</h3>
<p>Set your slicer's support threshold 5\u00b0 below your limit. If your limit is 45\u00b0, set supports to kick in at 40\u00b0. If even 20\u00b0 looks bad, check your part cooling fan speed.</p>''',
        'related': 'https://print3dbuddy.com/posts/how-to-calibrate-your-first-3d-printer/',
        'related_label': 'Full calibration guide',
    },
    {
        'id': 'retraction-test',
        'title': 'Retraction / Stringing Test',
        'tagline': 'Dial in retraction and eliminate stringing for good',
        'tag': 'Retraction',
        'summary': 'Seven thin towers spaced 20mm apart force the printhead to travel across open air on every pass. Any excess filament oozing from the nozzle shows up as strings or blobs between the towers. Adjust retraction distance and temperature until the towers print clean \u2014 that\'s your dialled-in setting.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>7 thin pillars the printhead must travel between without extruding. Any oozing shows up as strings or blobs.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">How to run it</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Print at your normal settings.</li>
  <li>Check for threads or blobs between the towers.</li>
  <li>Strings present: increase retraction by 0.5mm, reprint.</li>
  <li>Towers look blobby: too much retraction \u2014 reduce by 0.5mm steps.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Quick reference</h3>
<ul style="margin:0 0 0 20px;">
  <li><strong>Direct drive:</strong> start at 1\u20132mm retraction</li>
  <li><strong>Bowden:</strong> start at 4\u20136mm retraction</li>
  <li><strong>Still stringing?</strong> Drop nozzle temp by 5\u00b0C</li>
</ul>''',
        'related': 'https://print3dbuddy.com/posts/how-to-fix-3d-printer-stringing/',
        'related_label': 'Full stringing fix guide',
    },
    {
        'id': 'bridging-test',
        'title': 'Bridging Test',
        'tagline': 'Find the longest span your printer can cross without supports',
        'tag': 'Bridging',
        'summary': 'Five bridge sections spanning 10mm to 50mm, printed with nothing underneath. Flip the finished print and inspect each underside \u2014 a successful bridge is flat and smooth, a failing one sags. Knowing your bridge limit means you can model and slice with or without supports intelligently.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>5 pairs of pillars with bridges spanning 10, 20, 30, 40, and 50mm. Bridging is printed in mid-air with nothing underneath.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">How to run it</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Print with no supports at your normal settings.</li>
  <li>Flip the print and look at the underside of each bridge.</li>
  <li>Find the longest span that is flat and clean \u2014 that is your bridging limit.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">If bridges are sagging</h3>
<ul style="margin:0 0 0 20px;">
  <li>Reduce bridge speed to 50% of normal</li>
  <li>Set part cooling fan to 100%</li>
  <li>Drop nozzle temp by 5\u00b0C</li>
</ul>''',
        'related': 'https://print3dbuddy.com/posts/3d-printing-supports-guide/',
        'related_label': 'Full supports guide',
    },
    {
        'id': 'first-layer-test',
        'title': 'First Layer Calibration',
        'tagline': 'Get your Z offset right and nail first layer adhesion',
        'tag': 'First Layer',
        'summary': 'A thin 60\u00d760mm grid square that makes your first layer immediately readable. Lines that merge together mean the nozzle is too close; lines that won\'t stick mean it\'s too far. Takes under 5 minutes to print and gives you a concrete target to tune your Z offset against.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>A thin square (3 layers, 0.6mm total) with a raised grid pattern. Shows exactly how your first layer is landing across the whole print surface.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">How to run it</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Print at 0.2mm layer height (3 layers total = 0.6mm).</li>
  <li>Watch the first layer live, then inspect the finished print.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Reading the result</h3>
<ul style="margin:0 0 0 20px;">
  <li><strong>Grid lines merge:</strong> nozzle too close \u2014 raise Z offset by 0.05mm</li>
  <li><strong>Lines gappy or not sticking:</strong> nozzle too far \u2014 lower Z by 0.05mm</li>
  <li><strong>Elephant foot on circles:</strong> nozzle too close</li>
  <li><strong>Correct:</strong> lines slightly squished, separate, circles round</li>
</ul>''',
        'related': 'https://print3dbuddy.com/posts/3d-printing-first-layer-problems-fixes/',
        'related_label': 'First layer problems guide',
    },
    {
        'id': 'temp-tower',
        'title': 'Temperature Tower',
        'tagline': 'Find the ideal printing temperature for any filament',
        'tag': 'Temperature',
        'summary': 'Six stacked segments printed at descending temperatures from 220\u00b0C to 195\u00b0C, each with a small overhang tab. Compare surface finish, stringing, and overhang quality across the segments to find the sweet spot for a specific filament brand. Useful every time you switch to an unfamiliar spool.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>6 stacked segments (220\u00b0C down to 195\u00b0C), each with a small overhang tab. Comparing segments shows how temperature affects surface finish, stringing, and overhang quality.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Slicer setup</h3>
<p>Add a temperature change at each height:</p>
<ul style="margin:0 0 12px 20px;">
  <li>Z 3\u201313mm: 220\u00b0C &nbsp; Z 13\u201323mm: 215\u00b0C &nbsp; Z 23\u201333mm: 210\u00b0C</li>
  <li>Z 33\u201343mm: 205\u00b0C &nbsp; Z 43\u201353mm: 200\u00b0C &nbsp; Z 53\u201363mm: 195\u00b0C</li>
</ul>
<p>In OrcaSlicer/PrusaSlicer: use "Change filament temperature at layer". In Cura: use the ChangeAtZ plugin.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Reading the result</h3>
<p>Find the segment with a flat overhang tab, no stringing, and smooth walls. Too hot = stringing and drooping. Too cold = rough surface and weak layer adhesion.</p>''',
        'related': 'https://print3dbuddy.com/posts/pla-vs-petg-vs-abs-which-filament-for-beginners/',
        'related_label': 'Filament comparison guide',
    },
    {
        'id': 'flow-rate-test',
        'title': 'Flow Rate Test',
        'tagline': 'Dial in your extrusion multiplier for clean, accurate prints',
        'tag': 'Flow Rate',
        'summary': 'Five flat tiles labelled 90% to 110% - each sliced with its corresponding flow rate in the slicer. Print all five, compare the top surfaces, and the smoothest tile with no gaps or ridges tells you your correct extrusion multiplier. Takes about 20 minutes and removes the guesswork from flow calibration.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>5 flat tiles (30x30x4mm), labelled 90% through 110%. Each one is sliced with a different flow rate (extrusion multiplier) so you can compare results side by side.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Slicer setup</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Import the STL and split into individual objects in your slicer.</li>
  <li>Set each tile's flow/extrusion multiplier to its label: 0.90, 0.95, 1.00, 1.05, 1.10.</li>
  <li>Print all 5 at once at your normal speed and temperature.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Reading the result</h3>
<ul style="margin:0 0 0 20px;">
  <li><strong>Gaps or rough top surface:</strong> flow too low - move up one tile</li>
  <li><strong>Ridges, blobbing, or raised seam:</strong> flow too high - move down one tile</li>
  <li><strong>Smooth, flat, consistent surface:</strong> that is your correct flow rate</li>
</ul>
<p style="margin-top:10px;">Dial in to the nearest 1% from there. Most filaments land between 95-100%.</p>''',
        'related': 'https://print3dbuddy.com/posts/how-to-calibrate-flow-rate-extrusion-multiplier/',
        'related_label': 'Flow rate calibration guide',
    },
    {
        'id': 'ironing-test',
        'title': 'Ironing Test',
        'tagline': 'Find the right ironing settings for glass-smooth top surfaces',
        'tag': 'Ironing',
        'summary': 'Four flat tiles - one with no ironing as a baseline, then three with ironing enabled at 10%, 15%, and 20% flow. Split them in your slicer, assign the settings, and print all four. The tile with the smoothest, most glossy top surface is your ideal ironing flow rate.',
        'guide': '''<h3 style="font-size:0.95rem;margin:0 0 8px;">What it tests</h3>
<p>4 flat tiles (40x40x3mm). Tile 1 is printed without ironing as a baseline. Tiles 2-4 have ironing enabled at increasing flow rates so you can see the difference directly.</p>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Slicer setup</h3>
<ol style="margin:0 0 12px 20px;">
  <li>Import the STL and split into individual objects.</li>
  <li>Tile 1: ironing off. Tiles 2-4: ironing on at 10%, 15%, 20% flow.</li>
  <li>Set ironing speed to 50% of your normal print speed for all ironed tiles.</li>
  <li>Print all 4 at once.</li>
</ol>
<h3 style="font-size:0.95rem;margin:14px 0 8px;">Reading the result</h3>
<ul style="margin:0 0 0 20px;">
  <li><strong>Shiny, smooth, flat surface:</strong> correct setting</li>
  <li><strong>Still looks rough or uneven:</strong> try a higher flow or slower speed</li>
  <li><strong>Grooves or lines visible:</strong> spacing too wide - reduce ironing line spacing in slicer</li>
  <li><strong>Over-extruded ridges:</strong> flow too high - drop by 5%</li>
</ul>
<p style="margin-top:10px;">Most PLA lands at 10-15% flow. PETG often needs 15-20%. Works best on flat top surfaces.</p>''',
        'related': 'https://print3dbuddy.com/posts/3d-printing-ironing-guide/',
        'related_label': 'Ironing settings guide',
    },
]


@app.route('/test-prints')
def test_prints():
    return render_template('test_prints.html', user=get_current_user(), prints=TEST_PRINTS)


# ── Quick Guides ───────────────────────────────────────────────────────────────

QUICK_GUIDES = [
    {
        'id': 'fdm-troubleshooting',
        'title': 'FDM Troubleshooting Reference',
        'tagline': 'Every common FDM problem, cause, and fix in one place.',
        'tag': 'Troubleshooting',
        'icon': '🔧',
        'covers': ['Stringing, warping, layer adhesion', 'Under/over extrusion', 'Bed adhesion issues', 'Clogged nozzles', 'Quick-reference fix tables'],
        'content': '''
<h2>Stringing &amp; Oozing</h2>
<table>
  <tr><th>Symptom</th><th>Likely Cause</th><th>Fix</th></tr>
  <tr><td>Fine hair-like strings between parts</td><td>Temp too high</td><td>Drop nozzle temp 5°C at a time</td></tr>
  <tr><td>Thick strings / blobs</td><td>Retraction too low</td><td>Increase retraction: DD 0.5–1mm, Bowden 1mm steps</td></tr>
  <tr><td>Strings only on long travels</td><td>No retraction on travel</td><td>Enable "retract on layer change" + combing mode</td></tr>
  <tr><td>Strings even with high retraction</td><td>Partial clog / wet filament</td><td>Cold pull + dry filament</td></tr>
</table>
<div class="tip"><strong>Tip:</strong> Fix temp before retraction. Most stringing is a temperature problem.</div>

<h2>Bed Adhesion</h2>
<table>
  <tr><th>Symptom</th><th>Likely Cause</th><th>Fix</th></tr>
  <tr><td>First layer not sticking</td><td>Z offset too high</td><td>Lower Z offset by 0.05mm increments</td></tr>
  <tr><td>Corners lifting mid-print</td><td>Warping (temp / enclosure)</td><td>Increase bed temp, add brim, use enclosure for ABS</td></tr>
  <tr><td>Print pops off when cold</td><td>PEI working correctly</td><td>Wait for bed to cool below 35°C before removing</td></tr>
  <tr><td>Print won't release when cool</td><td>Z offset too low / over-squish</td><td>Raise Z offset slightly</td></tr>
  <tr><td>Elephant foot on first layer</td><td>Nozzle too close</td><td>Raise Z offset 0.05mm at a time</td></tr>
</table>

<h2>Under-Extrusion</h2>
<table>
  <tr><th>Symptom</th><th>Likely Cause</th><th>Fix</th></tr>
  <tr><td>Gaps in top surface</td><td>Flow rate too low</td><td>Increase flow rate 2–3%</td></tr>
  <tr><td>Extruder clicking</td><td>Partial clog or temp too low</td><td>Cold pull, increase temp 5°C</td></tr>
  <tr><td>Weak / snapping prints</td><td>Under-extrusion + low temp</td><td>Increase temp + check flow rate</td></tr>
  <tr><td>Gaps only on top layers</td><td>Too few top layers</td><td>Increase top layers to 5–6</td></tr>
</table>
<div class="warn"><strong>Check first:</strong> Extruder arm tension, PTFE tube condition, and bowden coupler for play.</div>

<h2>Layer Adhesion &amp; Splitting</h2>
<table>
  <tr><th>Symptom</th><th>Likely Cause</th><th>Fix</th></tr>
  <tr><td>Layers split when bent</td><td>Temp too low</td><td>Increase nozzle temp 5°C</td></tr>
  <tr><td>Visible layer lines / weak walls</td><td>Speed too high</td><td>Reduce speed 20%</td></tr>
  <tr><td>Delamination on ABS/ASA</td><td>Drafts / no enclosure</td><td>Fully enclose printer, reduce cooling fan</td></tr>
</table>

<h2>Material Quick-Reference Settings</h2>
<table>
  <tr><th>Material</th><th>Nozzle °C</th><th>Bed °C</th><th>Fan</th><th>Enclosure</th></tr>
  <tr><td>PLA</td><td>190–220</td><td>0–60</td><td>100%</td><td>No</td></tr>
  <tr><td>PETG</td><td>230–250</td><td>70–85</td><td>30–50%</td><td>Optional</td></tr>
  <tr><td>ABS</td><td>230–250</td><td>100–110</td><td>0–20%</td><td>Yes</td></tr>
  <tr><td>ASA</td><td>240–260</td><td>90–110</td><td>0–20%</td><td>Yes</td></tr>
  <tr><td>TPU (95A)</td><td>220–240</td><td>30–60</td><td>30%</td><td>No</td></tr>
  <tr><td>Nylon (PA)</td><td>240–270</td><td>70–90</td><td>0–20%</td><td>Yes</td></tr>
</table>

<h2>Nozzle Clogs</h2>
<h3>Cold Pull Method</h3>
<ol>
  <li>Heat nozzle to print temp and push filament through manually.</li>
  <li>Cool nozzle to 80–90°C (PLA) or 100°C (PETG/ABS).</li>
  <li>Pull filament firmly and quickly straight out.</li>
  <li>Repeat 3–5 times until the pulled tip comes out clean.</li>
</ol>
<div class="tip"><strong>Tip:</strong> Nylon filament works best for cold pulls - it's flexible enough to pull cleanly and grips debris well.</div>
'''
    },
    {
        'id': 'orcaslicer-guide',
        'title': 'OrcaSlicer Quick Guide',
        'tagline': 'Key settings, calibration tools, and workflows for OrcaSlicer.',
        'tag': 'Software',
        'icon': '🖥',
        'covers': ['First-time setup', 'Key print settings explained', 'Built-in calibration tools', 'Supports and multi-plate', 'Recommended profiles'],
        'content': '''
<h2>First-Time Setup</h2>
<h3>Add Your Printer</h3>
<ol>
  <li>Open OrcaSlicer → Printer icon top-left → Add Printer.</li>
  <li>Select your printer from the list, or choose a generic profile (FDM Generic).</li>
  <li>Set your nozzle diameter (usually 0.4mm).</li>
  <li>Set your build volume - check your printer specs if unsure.</li>
</ol>
<h3>Add a Filament Profile</h3>
<ol>
  <li>Filament dropdown → "+" → choose material type (PLA, PETG etc.).</li>
  <li>Set nozzle and bed temperatures for your specific brand.</li>
  <li>Save the profile with a name (e.g. "eSUN PLA+ White").</li>
</ol>
<div class="tip"><strong>Tip:</strong> Use the vendor's stated temperatures as a starting point, then run a temp tower to dial in the exact value.</div>

<h2>Key Settings Reference</h2>
<table>
  <tr><th>Setting</th><th>What It Does</th><th>Typical Value</th></tr>
  <tr><td>Layer Height</td><td>Vertical resolution / speed trade-off</td><td>0.2mm (standard), 0.12mm (quality), 0.28mm (draft)</td></tr>
  <tr><td>Wall Loops</td><td>Number of outer perimeters</td><td>3–4 for strength, 2 for draft</td></tr>
  <tr><td>Top/Bottom Layers</td><td>Solid layers capping the infill</td><td>4–5 minimum</td></tr>
  <tr><td>Infill Density</td><td>Internal fill percentage</td><td>15% decorative, 20–30% functional</td></tr>
  <tr><td>Infill Pattern</td><td>Shape of internal structure</td><td>Gyroid (strength), Grid (speed)</td></tr>
  <tr><td>Sparse Infill Speed</td><td>Speed for internal fill</td><td>200–300mm/s (Bambu), 60–80mm/s (Ender)</td></tr>
  <tr><td>Flow Ratio</td><td>Extrusion multiplier</td><td>Start at 0.98, calibrate per filament</td></tr>
  <tr><td>Retraction Length</td><td>Filament pullback on travel</td><td>0.5–1mm DD, 3–6mm Bowden</td></tr>
</table>

<h2>Built-In Calibration Tools</h2>
<p>OrcaSlicer has the best built-in calibration of any slicer. Access via: <strong>Calibration menu (top bar)</strong>.</p>
<table>
  <tr><th>Tool</th><th>What It Calibrates</th><th>When to Use</th></tr>
  <tr><td>Temp Tower</td><td>Ideal nozzle temperature</td><td>Every new filament</td></tr>
  <tr><td>Flow Rate</td><td>Extrusion multiplier</td><td>Every new filament brand</td></tr>
  <tr><td>Pressure Advance</td><td>Corner quality / blobs</td><td>After changing speeds or nozzle</td></tr>
  <tr><td>Retraction Test</td><td>Retraction distance</td><td>When stringing appears</td></tr>
  <tr><td>Max Volumetric Speed</td><td>Highest reliable flow rate</td><td>When pushing for speed</td></tr>
</table>
<div class="tip"><strong>Tip:</strong> Run Flow Rate first, then Pressure Advance. Order matters - PA calibration assumes flow rate is already correct.</div>

<h2>Supports</h2>
<table>
  <tr><th>Setting</th><th>Recommendation</th></tr>
  <tr><td>Support type</td><td>Tree (auto) for organic shapes, Normal for flat overhangs</td></tr>
  <tr><td>Threshold angle</td><td>Set 5° below your tested overhang limit</td></tr>
  <tr><td>Z distance</td><td>0.2mm (PLA), 0.25mm (PETG)</td></tr>
  <tr><td>Interface layers</td><td>2–3 layers, 0.2mm spacing - makes removal much cleaner</td></tr>
  <tr><td>Support on build plate only</td><td>Enable to avoid supports mid-air on complex geometry</td></tr>
</table>

<h2>Multi-Plate Printing</h2>
<ol>
  <li>Add objects to the plate normally - OrcaSlicer auto-arranges.</li>
  <li>To add a second plate: click "+" next to the plate tab at the bottom.</li>
  <li>Objects can have different settings per-plate (useful for different materials).</li>
  <li>Slice All Plates to process everything at once before exporting.</li>
</ol>
'''
    },
    {
        'id': 'prusaslicer-guide',
        'title': 'PrusaSlicer Quick Guide',
        'tagline': 'Key settings, multi-material setup, and calibration in PrusaSlicer.',
        'tag': 'Software',
        'icon': '🐻',
        'covers': ['First-time setup', 'Print / filament / printer profiles', 'Supports and painting', 'Variable layer height', 'Multi-material (MMU)'],
        'content': '''
<h2>First-Time Setup</h2>
<h3>Configuration Wizard</h3>
<ol>
  <li>First launch opens the Configuration Wizard automatically.</li>
  <li>Select your printer - most Prusa, Creality, Bambu, and generic printers are listed.</li>
  <li>Choose your nozzle diameter and build volume.</li>
  <li>Select filament profiles to install (PLA, PETG, ABS etc.).</li>
</ol>
<div class="tip"><strong>Tip:</strong> You can re-run the wizard any time from Help → Configuration Wizard.</div>

<h2>The Three Profile Types</h2>
<table>
  <tr><th>Profile Type</th><th>What It Controls</th><th>Where to Find It</th></tr>
  <tr><td>Print Settings</td><td>Layer height, infill, speeds, supports</td><td>Left dropdown - "Print settings"</td></tr>
  <tr><td>Filament Settings</td><td>Temperatures, cooling, retraction</td><td>Middle dropdown - "Filament"</td></tr>
  <tr><td>Printer Settings</td><td>Build volume, nozzle, bed shape</td><td>Right dropdown - "Printer"</td></tr>
</table>
<p>Changes to a profile without saving create an unsaved override (marked with *). Save profiles via the floppy disk icon.</p>

<h2>Key Print Settings Reference</h2>
<table>
  <tr><th>Setting</th><th>Typical Value</th><th>Notes</th></tr>
  <tr><td>Layer height</td><td>0.2mm</td><td>Max 75% of nozzle diameter</td></tr>
  <tr><td>Perimeters</td><td>3</td><td>Increase to 4–5 for strong parts</td></tr>
  <tr><td>Top/Bottom solid layers</td><td>4</td><td>5+ if top surface looks gappy</td></tr>
  <tr><td>Fill density</td><td>15–20%</td><td>25–40% for functional parts</td></tr>
  <tr><td>Fill pattern</td><td>Gyroid</td><td>Best all-round strength</td></tr>
  <tr><td>Extrusion multiplier</td><td>0.97–1.0</td><td>Calibrate per filament brand</td></tr>
  <tr><td>Print speed</td><td>50–80mm/s</td><td>Reduce for quality or overhangs</td></tr>
</table>

<h2>Support Painting</h2>
<p>PrusaSlicer's support painting lets you add or remove supports on specific faces of a model rather than relying entirely on auto-generation.</p>
<ol>
  <li>Select a model → click the Support Painter icon (paint palette) on the toolbar.</li>
  <li>Green brush = enforce supports on that face.</li>
  <li>Red brush = block supports on that face.</li>
  <li>Useful for models where auto supports are excessive or placed wrong.</li>
</ol>
<div class="tip"><strong>Tip:</strong> Combine auto supports with painting - let PrusaSlicer generate first, then paint over problem areas.</div>

<h2>Variable Layer Height</h2>
<p>Prints flat sections fast at 0.3mm and detailed sections slow at 0.1mm automatically.</p>
<ol>
  <li>Select model → click the Layer Height icon on the toolbar.</li>
  <li>Click "Adaptive" to auto-assign heights based on surface slope.</li>
  <li>Manually drag the layer height curve to override specific Z ranges.</li>
  <li>Can cut print time 20–40% on models with large flat sections.</li>
</ol>

<h2>Useful Keyboard Shortcuts</h2>
<table>
  <tr><th>Key</th><th>Action</th></tr>
  <tr><td>Ctrl + L</td><td>Import STL</td></tr>
  <tr><td>Ctrl + Shift + L</td><td>Import and orient on plate</td></tr>
  <tr><td>A</td><td>Auto-arrange all objects</td></tr>
  <tr><td>M</td><td>Move tool</td></tr>
  <tr><td>R</td><td>Rotate tool</td></tr>
  <tr><td>S</td><td>Scale tool</td></tr>
  <tr><td>Ctrl + E</td><td>Export G-code</td></tr>
</table>
'''
    },
    {
        'id': 'cura-guide',
        'title': 'Cura Quick Guide',
        'tagline': 'Essential settings, plugins, and profiles for Ultimaker Cura.',
        'tag': 'Software',
        'icon': '🖨️',
        'covers': ['Printer setup', 'Custom vs recommended settings', 'Most important settings explained', 'Useful plugins', 'Profile import/export'],
        'content': '''
<h2>Adding Your Printer</h2>
<ol>
  <li>Settings → Printers → Add Printer.</li>
  <li>Search for your printer model. If not listed, choose "Custom FFF Printer".</li>
  <li>For custom: set X/Y/Z build volume, nozzle diameter, and heated bed (yes/no).</li>
  <li>Set the machine start/end G-code if your printer requires it - check manufacturer docs.</li>
</ol>
<div class="tip"><strong>Tip:</strong> Cura has profiles for 500+ printers. Check for your model before creating a custom one.</div>

<h2>Recommended vs Custom Profiles</h2>
<table>
  <tr><th>Mode</th><th>When to Use</th></tr>
  <tr><td>Recommended (Simple)</td><td>Quick prints, familiar models, when you just want it to work</td></tr>
  <tr><td>Custom</td><td>Any time quality matters or you're troubleshooting - gives access to all 400+ settings</td></tr>
</table>
<p>Switch between modes via the button at the top of the settings panel. Custom mode remembers your settings between sessions.</p>

<h2>Key Settings Reference</h2>
<table>
  <tr><th>Setting</th><th>Typical Value</th><th>Notes</th></tr>
  <tr><td>Layer Height</td><td>0.2mm</td><td>0.12 for quality, 0.28 for speed</td></tr>
  <tr><td>Wall Line Count</td><td>3</td><td>4 for strong functional parts</td></tr>
  <tr><td>Top/Bottom Layers</td><td>4</td><td>Increase if top surface is rough</td></tr>
  <tr><td>Infill Density</td><td>20%</td><td>15% decorative, 30–40% structural</td></tr>
  <tr><td>Infill Pattern</td><td>Gyroid</td><td>Or "Lines" for fastest print time</td></tr>
  <tr><td>Print Speed</td><td>50mm/s</td><td>Reduce to 30–40 for better quality</td></tr>
  <tr><td>Flow</td><td>100%</td><td>Calibrate per filament - often 97–100%</td></tr>
  <tr><td>Retraction Distance</td><td>5–6mm Bowden, 1–2mm DD</td><td>Reduce if grinding occurs</td></tr>
  <tr><td>Support Z Distance</td><td>0.2mm</td><td>Increase to 0.25 for PETG</td></tr>
</table>

<h2>Useful Plugins (Marketplace)</h2>
<table>
  <tr><th>Plugin</th><th>What It Does</th></tr>
  <tr><td>ChangeAtZ</td><td>Change any setting at a specific layer height - essential for temp towers</td></tr>
  <tr><td>Mesh Tools</td><td>Fix broken STL geometry before slicing</td></tr>
  <tr><td>Auto-Orientation</td><td>Automatically rotates models for best print orientation</td></tr>
  <tr><td>Calibration Shapes</td><td>Generates calibration cubes, towers, and test prints inside Cura</td></tr>
  <tr><td>Support Eraser</td><td>Block supports on specific areas of a model</td></tr>
</table>
<p>Install plugins: Help → Marketplace → search plugin name → Install → restart Cura.</p>

<h2>Profile Import / Export</h2>
<ol>
  <li><strong>Export:</strong> Preferences → Profiles → select profile → Export. Saves as .curaprofile file.</li>
  <li><strong>Import:</strong> Preferences → Profiles → Import → select .curaprofile file.</li>
  <li>Share profiles between machines or save backups before upgrading Cura versions.</li>
</ol>
<div class="warn"><strong>Warning:</strong> Cura profiles are version-specific. A profile saved in Cura 5.6 may not import correctly into 5.4.</div>
'''
    },
    {
        'id': 'filament-reference',
        'title': 'Filament Quick Reference',
        'tagline': 'Settings tables, properties, and tips for every common filament.',
        'tag': 'Materials',
        'icon': '🧵',
        'covers': ['PLA, PETG, ABS, ASA, TPU, Nylon', 'Settings tables per material', 'Storage requirements', 'Common problems per material', 'Material comparison chart'],
        'content': '''
<h2>PLA</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>190–220°C</td></tr>
  <tr><td>Bed temp</td><td>0–60°C (no heated bed needed)</td></tr>
  <tr><td>Cooling fan</td><td>100%</td></tr>
  <tr><td>Enclosure</td><td>Not needed</td></tr>
  <tr><td>Retraction (DD)</td><td>0.5–1mm</td></tr>
  <tr><td>Retraction (Bowden)</td><td>4–6mm</td></tr>
  <tr><td>Heat resistance</td><td>~55–60°C</td></tr>
  <tr><td>Moisture sensitive</td><td>Low - but store sealed for best results</td></tr>
</table>
<div class="tip"><strong>Best for:</strong> Decorative prints, miniatures, household items, learning projects. Anything that won't see heat or heavy stress.</div>

<h2>PETG</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>230–250°C</td></tr>
  <tr><td>Bed temp</td><td>70–85°C</td></tr>
  <tr><td>Cooling fan</td><td>30–50% (too much = poor layer adhesion)</td></tr>
  <tr><td>Enclosure</td><td>Not required, helpful for large prints</td></tr>
  <tr><td>Retraction (DD)</td><td>1–2mm</td></tr>
  <tr><td>Retraction (Bowden)</td><td>5–7mm</td></tr>
  <tr><td>Heat resistance</td><td>~75–80°C</td></tr>
  <tr><td>Moisture sensitive</td><td>High - dry before use, seal when storing</td></tr>
</table>
<div class="warn"><strong>Watch out:</strong> PETG sticks aggressively to glass beds. Use PEI or add a thin release layer (glue stick).</div>

<h2>ABS</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>230–250°C</td></tr>
  <tr><td>Bed temp</td><td>100–110°C</td></tr>
  <tr><td>Cooling fan</td><td>0–20% maximum</td></tr>
  <tr><td>Enclosure</td><td>Required - warps badly in drafts</td></tr>
  <tr><td>Heat resistance</td><td>~90–100°C</td></tr>
  <tr><td>Moisture sensitive</td><td>Medium</td></tr>
</table>
<div class="tip"><strong>Best for:</strong> High-heat environments, automotive parts, functional parts that need acetone smoothing.</div>

<h2>ASA</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>240–260°C</td></tr>
  <tr><td>Bed temp</td><td>90–110°C</td></tr>
  <tr><td>Cooling fan</td><td>0–20%</td></tr>
  <tr><td>Enclosure</td><td>Required</td></tr>
  <tr><td>Heat resistance</td><td>~95–100°C</td></tr>
  <tr><td>UV resistance</td><td>Excellent - better than ABS outdoors</td></tr>
</table>
<div class="tip"><strong>Best for:</strong> Outdoor use, UV exposure, as a better alternative to ABS for most applications.</div>

<h2>TPU (Flexible)</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>220–240°C</td></tr>
  <tr><td>Bed temp</td><td>30–60°C</td></tr>
  <tr><td>Cooling fan</td><td>30%</td></tr>
  <tr><td>Print speed</td><td>20–30mm/s - slow is essential</td></tr>
  <tr><td>Retraction</td><td>Minimal or off - causes jams on Bowden</td></tr>
  <tr><td>Direct drive</td><td>Strongly preferred - Bowden very difficult</td></tr>
</table>
<div class="warn"><strong>Watch out:</strong> TPU jams in Bowden tubes easily. If using Bowden, disable retraction entirely and print very slowly.</div>

<h2>Nylon (PA)</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Nozzle temp</td><td>240–270°C</td></tr>
  <tr><td>Bed temp</td><td>70–90°C</td></tr>
  <tr><td>Cooling fan</td><td>20–50%</td></tr>
  <tr><td>Enclosure</td><td>Recommended</td></tr>
  <tr><td>Moisture sensitive</td><td>Very high - must be bone-dry before printing</td></tr>
</table>
<div class="warn"><strong>Critical:</strong> Nylon absorbs moisture faster than any other common filament. Dry at 70°C for 8+ hours before every print.</div>

<h2>Material Comparison</h2>
<table>
  <tr><th>Material</th><th>Ease</th><th>Heat Resist.</th><th>Strength</th><th>Outdoor</th></tr>
  <tr><td>PLA</td><td>⭐⭐⭐⭐⭐</td><td>Low</td><td>Medium</td><td>Poor</td></tr>
  <tr><td>PETG</td><td>⭐⭐⭐⭐</td><td>Medium</td><td>High</td><td>Fair</td></tr>
  <tr><td>ABS</td><td>⭐⭐</td><td>High</td><td>High</td><td>Fair</td></tr>
  <tr><td>ASA</td><td>⭐⭐</td><td>High</td><td>High</td><td>Excellent</td></tr>
  <tr><td>TPU</td><td>⭐⭐⭐</td><td>Medium</td><td>Flexible</td><td>Good</td></tr>
  <tr><td>Nylon</td><td>⭐⭐</td><td>High</td><td>Very High</td><td>Good</td></tr>
</table>

<h2>Storage Guide</h2>
<table>
  <tr><th>Material</th><th>Storage Priority</th><th>Dry If:</th></tr>
  <tr><td>PLA</td><td>Low - sealed bag is fine</td><td>Popping sounds or rough surface</td></tr>
  <tr><td>PETG</td><td>High - absorbs fast</td><td>Any stringing or bubbling</td></tr>
  <tr><td>ABS</td><td>Medium</td><td>Popping or splitting layers</td></tr>
  <tr><td>TPU</td><td>High</td><td>Stringing or rough surface</td></tr>
  <tr><td>Nylon</td><td>Critical - dry before every use</td><td>Always dry before printing</td></tr>
</table>
'''
    },
    {
        'id': 'calibration-checklist',
        'title': 'Calibration Checklist',
        'tagline': 'The correct order for calibrating any FDM printer from scratch.',
        'tag': 'Calibration',
        'icon': '✅',
        'covers': ['Step-by-step calibration order', 'E-steps / rotation distance', 'Bed levelling and Z offset', 'Flow rate and pressure advance', 'When to re-calibrate'],
        'content': '''
<h2>Why Order Matters</h2>
<p>Each calibration step builds on the last. Calibrating flow rate before e-steps means you're compensating for a hardware problem with a software value - and it'll drift every time you change anything. Do it in this order, every time.</p>

<h2>The Calibration Checklist</h2>
<ul class="checklist">
  <li><strong>Step 1: E-steps / Rotation Distance</strong> - How many motor steps push exactly 100mm of filament. Do this first on a new printer or after changing the extruder.</li>
  <li><strong>Step 2: Bed Levelling</strong> - Ensure the bed is physically flat and level relative to the gantry. Manual: paper method. Auto: run BLTouch/CR Touch mesh levelling.</li>
  <li><strong>Step 3: Z Offset</strong> - Fine-tune the nozzle-to-bed gap. Too close = elephant foot, too far = won't stick. Adjust in 0.05mm steps.</li>
  <li><strong>Step 4: Temperature Tower</strong> - Find the ideal nozzle temperature for your specific filament brand and colour. Run once per new filament.</li>
  <li><strong>Step 5: Flow Rate / Extrusion Multiplier</strong> - Calibrate how much filament actually comes out vs what the slicer expects. Calibrate per filament profile.</li>
  <li><strong>Step 6: Pressure Advance / Linear Advance</strong> - Compensates for filament pressure lag in corners. Run after any significant speed or temperature change.</li>
  <li><strong>Step 7: Retraction</strong> - Tune retraction distance and speed to eliminate stringing. Run after pressure advance is set.</li>
</ul>

<h2>E-Steps Calibration</h2>
<ol>
  <li>Mark filament 120mm above the extruder entry with a marker.</li>
  <li>Heat to print temp. Command 100mm extrusion via console (M83, then G1 E100 F100).</li>
  <li>Measure the distance from the mark to the extruder. If 20mm remains, actual = 100mm. If 18mm remains, actual = 102mm.</li>
  <li>New e-steps = (current e-steps × 100) ÷ actual mm extruded.</li>
  <li>Set via M92 E[new value], save with M500.</li>
</ol>
<div class="tip"><strong>Klipper:</strong> Use rotation_distance instead of e-steps. New value = old rotation_distance × (actual / 100).</div>

<h2>Z Offset Quick Reference</h2>
<table>
  <tr><th>First Layer Appearance</th><th>Adjustment</th></tr>
  <tr><td>Lines merge together / flat blob</td><td>Raise Z offset +0.05mm</td></tr>
  <tr><td>Lines don't stick / gaps visible</td><td>Lower Z offset -0.05mm</td></tr>
  <tr><td>Elephant foot on edges</td><td>Raise Z offset +0.05mm</td></tr>
  <tr><td>Circles look squished or oval</td><td>Raise Z offset +0.05mm</td></tr>
  <tr><td>Lines slightly squished, separate, round circles</td><td>Correct - no adjustment needed</td></tr>
</table>

<h2>When to Re-Calibrate</h2>
<table>
  <tr><th>Event</th><th>Re-calibrate</th></tr>
  <tr><td>New filament brand</td><td>Temp tower, flow rate</td></tr>
  <tr><td>New filament colour (same brand)</td><td>Temp tower (colour affects melt)</td></tr>
  <tr><td>Changed nozzle</td><td>Z offset, flow rate, pressure advance</td></tr>
  <tr><td>Changed extruder</td><td>E-steps + all of the above</td></tr>
  <tr><td>Moved printer</td><td>Bed level, Z offset</td></tr>
  <tr><td>Firmware update</td><td>Check e-steps / PA were retained</td></tr>
  <tr><td>Print quality degraded</td><td>Start from Step 2</td></tr>
</table>

<h2>Quick Troubleshooting During Calibration</h2>
<div class="tip"><strong>First layer won't stick after Z offset looks right:</strong> Check bed temperature, clean PEI with IPA, and make sure filament is dry.</div>
<div class="warn"><strong>E-steps look right but flow is still off:</strong> Check for partial nozzle clog, PTFE tube gap at hot end, or worn extruder gear.</div>
<div class="tip"><strong>Pressure advance makes corners worse:</strong> You may have set it too high. Start at 0.02 and increase in 0.005 steps until corners are clean.</div>
'''
    },
]


@app.route('/guides')
def guides():
    return render_template('guides.html', user=get_current_user(), guides=QUICK_GUIDES)

@app.route('/guides/<slug>')
@login_required
def guide_detail(slug):
    guide = next((g for g in QUICK_GUIDES if g['id'] == slug), None)
    if not guide:
        return 'Guide not found', 404
    return render_template('guide_detail.html', user=get_current_user(), guide=guide)


# ── STL Downloads ─────────────────────────────────────────────────────────────

STL_FILES = {
    'overhang-test':    'overhang_test.stl',
    'retraction-test':  'retraction_test.stl',
    'bridging-test':    'bridging_test.stl',
    'first-layer-test': 'first_layer_test.stl',
    'temp-tower':       'temp_tower.stl',
    'flow-rate-test':   'flow_rate_test.stl',
    'ironing-test':     'ironing_test.stl',
}

@app.route('/download/stl/<slug>')
@login_required
def download_stl(slug):
    user = get_current_user()
    if not user['is_paid']:
        flash('STL downloads are available to paid members. Upgrade below.', 'warning')
        return redirect(url_for('upgrade'))
    filename = STL_FILES.get(slug)
    if not filename:
        return 'Not found', 404
    return redirect(f'https://print3dbuddy.com/static/stl/{filename}')


@app.route('/sitemap.xml')
def sitemap():
    from flask import Response
    from datetime import date
    today = date.today().strftime('%Y-%m-%d')
    urls = [
        '/', '/test-prints', '/guides', '/register', '/login', '/upgrade',
        '/tools/filament-cost', '/tools/print-settings',
        '/tools/slicer-recommender', '/tools/stl-estimator',
    ]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for url in urls:
        xml += f'  <url><loc>https://tools.print3dbuddy.com{url}</loc><lastmod>{today}</lastmod></url>\n'
    xml += '</urlset>\n'
    return Response(xml, mimetype='application/xml')


init_db()

if __name__ == '__main__':
    print('Database initialised.')
    print('Starting server at http://localhost:5000')
    app.run(debug=True, port=5000)
