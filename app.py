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
]


@app.route('/test-prints')
def test_prints():
    return render_template('test_prints.html', user=get_current_user(), prints=TEST_PRINTS)


# ── STL Downloads ─────────────────────────────────────────────────────────────

STL_FILES = {
    'overhang-test':    'overhang_test.stl',
    'retraction-test':  'retraction_test.stl',
    'bridging-test':    'bridging_test.stl',
    'first-layer-test': 'first_layer_test.stl',
    'temp-tower':       'temp_tower.stl',
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
        '/', '/test-prints', '/register', '/login', '/upgrade',
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
