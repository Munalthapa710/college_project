from flask import Flask, render_template, request, redirect, session, jsonify, make_response, url_for # Added make_response, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import pytz
from functools import wraps # For decorators
from dijkstra import dijkstra, shortest_path 
from graph_with_coords import graph, coordinates 
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex() 

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

NPT = pytz.timezone('Asia/Kathmandu')

def format_datetime_npt(dt_utc):
    if dt_utc is None: return "N/A"
    if dt_utc.tzinfo is None or dt_utc.tzinfo.utcoffset(dt_utc) is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    else:
        dt_utc = dt_utc.astimezone(timezone.utc)
    dt_npt = dt_utc.astimezone(NPT)
    return dt_npt.strftime('%Y-%m-%d %H:%M NPT')

# --- Models ---
class RideRequest(db.Model):
    __tablename__ = 'ride_request'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), nullable=False)
    driver_email = db.Column(db.String(100), nullable=False)
    user_latitude_at_request = db.Column(db.Float, nullable=True)
    user_longitude_at_request = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='Pending')

class User(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100)) 
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

class Driver(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100)) 
    vehicle = db.Column(db.String(50))
    node = db.Column(db.String(10), nullable=False)

# --- Decorators for Authentication ---
def login_required_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def login_required_driver(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'driver' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Cache Control Helper ---
# The global @app.after_request was removed in favor of per-route explicit setting
# for authenticated HTML pages.

def add_no_cache_to_response(response):
    """Adds no-cache headers to a given Flask response object."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# --- Routes ---
@app.route('/')
def home(): return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST']) # Public route
def register():
    if request.method == 'POST':
        role = request.form['role']; name = request.form['name']; email = request.form['email']
        phone = request.form['phone']; password = request.form['password']; confirm = request.form['confirm_password']
        if password != confirm: return 'Passwords do not match.'
        if role == 'driver':
            if Driver.query.get(email): return 'Driver email exists.'
            vehicle = request.form['vehicle']; node = request.form.get('node')
            if not node or node not in coordinates: return 'Driver needs valid node.'
            db.session.add(Driver(email=email, name=name, phone=phone, password=password, vehicle=vehicle, node=node))
        else:
            if User.query.get(email): return 'User email exists.'
            db.session.add(User(email=email, name=name, phone=phone, password=password, latitude=None, longitude=None))
        try: db.session.commit(); return redirect(url_for('login'))
        except Exception as e: db.session.rollback(); print(f"RegErr:{e}"); return "RegErr",500
    return render_template('register.html', nodes=coordinates.keys())

@app.route('/login', methods=['GET', 'POST']) # Public route
def login():
    if request.method == 'POST':
        role = request.form['role']; email = request.form['username']; password = request.form['password']
        if role == 'driver':
            driver = Driver.query.get(email)
            if driver and driver.password == password: session['driver'] = driver.email; return redirect(url_for('dashboard'))
        elif role == 'user':
            user = User.query.get(email)
            if user and user.password == password: session['user'] = user.email; return redirect(url_for('user_dashboard'))
        return 'Invalid credentials.' 
    return render_template('login.html')

# --- API-like routes (return JSON, no specific HTML cache headers needed here) ---
@app.route('/set-user-current-location', methods=['POST'])
@login_required_user
def set_user_current_location():
    data = request.get_json();
    if not data: return jsonify({'error': 'No JSON', 'success': False}), 400
    lat_str, lng_str = data.get('latitude'), data.get('longitude')
    if lat_str is None or lng_str is None: return jsonify({'error': 'Lat/Lng missing', 'success': False}), 400
    try:
        lat, lng = float(lat_str), float(lng_str)
        if not (-90 <= lat <= 90 and -180 <= lng <= 180): raise ValueError("Coords out of range.")
    except (ValueError, TypeError) as ve: return jsonify({'error': f'Invalid lat/lng: {ve}', 'success': False}), 400
    user = User.query.get(session['user'])
    if user:
        user.latitude, user.longitude = lat, lng
        try: db.session.commit(); return jsonify({'success': True, 'latitude': lat, 'longitude': lng, 'message': f'Location updated to ({lat:.6f}, {lng:.6f})'}), 200
        except Exception as e: db.session.rollback(); print(f"DB Err: {e}"); return jsonify({'error': 'DB err setting loc', 'success': False}), 500
    return jsonify({'error': 'User not found', 'success': False}), 404

@app.route('/find-nearest-driver-dijkstra', methods=['POST'])
@login_required_user
def find_nearest_driver_dijkstra():
    data = request.get_json();
    if not data: return jsonify({'error': 'No JSON', 'success': False}), 400
    user_closest_node = data.get('user_closest_node')
    if not user_closest_node or user_closest_node not in graph or user_closest_node not in coordinates:
        return jsonify({'error': 'Invalid user_closest_node for Dijkstra.', 'success': False}), 400
    available_drivers = Driver.query.filter(Driver.node.isnot(None), Driver.node.in_(graph.keys())).all()
    nearest_driver_info = None; min_distance = float('inf')
    if not available_drivers: return jsonify({'message': 'No drivers available or their nodes are not in routing graph.', 'success': True, 'nearest_driver': None})
    for driver in available_drivers:
        distance = dijkstra(graph, user_closest_node, driver.node)
        if distance < min_distance:
            min_distance = distance
            path = shortest_path(graph, user_closest_node, driver.node)
            if path: nearest_driver_info = {'email': driver.email, 'name': driver.name, 'vehicle': driver.vehicle, 
                                          'node': driver.node, 'graph_distance': round(min_distance,2) if min_distance != float('inf') else "Unreachable", 
                                          'path_nodes': path}
            else: min_distance = float('inf') 
    if nearest_driver_info: return jsonify({'success': True, 'nearest_driver': nearest_driver_info})
    return jsonify({'message': 'No reachable drivers found via Dijkstra network path.', 'success': True, 'nearest_driver': None})

@app.route('/request-ride', methods=['POST'])
@login_required_user
def request_ride():
    data=request.get_json();
    if not data: return jsonify({'message': 'No JSON', 'success': False}), 400
    driver_email = data.get('driver_email')
    if not driver_email: return jsonify({'message': 'Driver email missing', 'success': False}), 400
    user_email = session['user']
    RideRequest.query.filter(RideRequest.user_email == user_email, RideRequest.status.in_(['Pending', 'accepted'])).update({'status': 'superseded'}, synchronize_session='fetch')
    user = User.query.get(user_email)
    if not user: return jsonify({'message': 'User not found', 'success': False}), 404
    if user.latitude is None or user.longitude is None: return jsonify({'message': 'Your precise location is not set.', 'success': False}), 400
    new_ride = RideRequest(user_email=user_email, driver_email=driver_email, user_latitude_at_request=user.latitude, user_longitude_at_request=user.longitude, status='Pending')
    db.session.add(new_ride); 
    try: db.session.commit(); return jsonify({'message': f'Ride requested successfully from {driver_email}!', 'success': True})
    except Exception as e: db.session.rollback();print(f"RideReqErr:{e}"); return jsonify({'message': 'Error requesting ride.', 'success': False}), 500

@app.route('/accept-request', methods=['POST'])
@login_required_driver
def accept_request():
    data=request.get_json(); req_id=data.get('id') if data else None
    if not req_id: return jsonify({'error': 'ID missing', 'success': False}), 400
    req = RideRequest.query.get(req_id)
    if not req or req.driver_email != session['driver'] or req.status != 'Pending': 
        return jsonify({'error': 'Invalid request or not pending', 'success': False}), 400
    if req.user_latitude_at_request is None or req.user_longitude_at_request is None:
        return jsonify({'error': 'User location missing for this ride.', 'success': False}), 400
    try: 
        req.status = 'accepted'; db.session.commit()
        return jsonify({'success': True, 'message': 'Ride accepted'}), 200
    except Exception as e: 
        db.session.rollback(); print(f"DBErr accept:{e}")
        return jsonify({'error': 'DB error accepting ride', 'success': False}), 500

@app.route('/reject-request', methods=['POST'])
@login_required_driver
def reject_request():
    data=request.get_json(); req_id=data.get('id') if data else None
    if not req_id: return jsonify({'error': 'ID missing', 'success': False}), 400
    req = RideRequest.query.get(req_id)
    if not req or req.driver_email != session['driver'] or req.status != 'Pending':
        return jsonify({'error': 'Invalid request or not pending', 'success': False}), 400
    try: 
        req.status = 'rejected'; db.session.commit()
        return jsonify({'success': True, 'message': 'Ride rejected'}), 200
    except Exception as e: 
        db.session.rollback(); print(f"DBErr reject:{e}")
        return jsonify({'error': 'DB error rejecting ride', 'success': False}), 500

@app.route('/complete-ride', methods=['POST'])
@login_required_driver
def complete_ride():
    data=request.get_json(); ride_id=data.get('ride_id') if data else None
    if not ride_id: return jsonify({'error': 'ID missing', 'success': False}), 400
    ride = RideRequest.query.get(ride_id)
    if not ride or ride.driver_email != session['driver']: 
        return jsonify({'error': 'Invalid ride or unauthorized', 'success': False}), 400
    if ride.status != 'accepted': 
        print(f"Warn: Completing ride {ride.id} not 'accepted' (was {ride.status})")
    try: 
        ride.status = 'completed'; db.session.commit()
        return jsonify({'success': True, 'message': 'Ride completed'}), 200
    except Exception as e: 
        db.session.rollback(); print(f"DBErr complete:{e}")
        return jsonify({'error': 'DB error completing ride', 'success': False}), 500

# --- HTML Rendering Routes with Explicit No-Cache Headers ---
@app.route('/dashboard') 
@login_required_driver
def dashboard():
    driver = Driver.query.get(session['driver'])
    # No additional null check needed due to decorator, but good for direct calls if any
    # if not driver or not driver.node or driver.node not in coordinates: ...
    pending_reqs_db = RideRequest.query.filter_by(driver_email=driver.email, status='Pending').order_by(RideRequest.timestamp.asc()).all()
    pending_serialized = []
    for r_db in pending_reqs_db:
        user_obj = User.query.get(r_db.user_email)
        if r_db.user_latitude_at_request is not None and r_db.user_longitude_at_request is not None:
            pending_serialized.append({'id':r_db.id, 'user_email': r_db.user_email, 'user_name':(user_obj.name if user_obj else "User"), 
                                       'user_latitude':r_db.user_latitude_at_request, 'user_longitude':r_db.user_longitude_at_request,
                                       'timestamp':format_datetime_npt(r_db.timestamp), 'status':r_db.status })
    active_ride_db = RideRequest.query.filter_by(driver_email=driver.email, status='accepted').first()
    active_ride_serialized = None
    if active_ride_db and active_ride_db.user_latitude_at_request is not None and active_ride_db.user_longitude_at_request is not None:
        user_obj = User.query.get(active_ride_db.user_email)
        active_ride_serialized = {'id':active_ride_db.id, 'user_email': active_ride_db.user_email, 'user_name':(user_obj.name if user_obj else "User"),
                                  'user_latitude':active_ride_db.user_latitude_at_request, 'user_longitude':active_ride_db.user_longitude_at_request,
                                  'timestamp':format_datetime_npt(active_ride_db.timestamp) }
    response = make_response(render_template('driver_dashboard.html', driver=driver, coords=coordinates,
                           pending_requests=pending_serialized, active_ride=active_ride_serialized))
    return add_no_cache_to_response(response)

@app.route('/user-dashboard')
@login_required_user
def user_dashboard():
    user = User.query.get(session['user'])
    drivers_js = [{'email':d.email, 'name':d.name, 'vehicle':d.vehicle, 'node':d.node} 
                  for d in Driver.query.filter(Driver.node.isnot(None)).all() if d.node in coordinates]
    status_info = None
    accepted_ride = RideRequest.query.filter_by(user_email=user.email, status='accepted').order_by(RideRequest.timestamp.desc()).first()
    if accepted_ride:
        driver = Driver.query.get(accepted_ride.driver_email)
        if driver and driver.node and driver.node in coordinates and \
           accepted_ride.user_latitude_at_request is not None and accepted_ride.user_longitude_at_request is not None:
            status_info = {'type':'accepted', 'driver_name':driver.name, 'driver_node':driver.node, 
                           'user_latitude_for_route':accepted_ride.user_latitude_at_request, 
                           'user_longitude_for_route':accepted_ride.user_longitude_at_request,
                           'timestamp':format_datetime_npt(accepted_ride.timestamp), 
                           'message':f"Ride with {driver.name} confirmed! En route."}
        else: status_info = {'type':'error', 'message':'Accepted ride location data error.', 'timestamp':format_datetime_npt(datetime.now(timezone.utc))}
    else:
        pending = RideRequest.query.filter_by(user_email=user.email, status='Pending').order_by(RideRequest.timestamp.desc()).first()
        if pending:
            driver = Driver.query.get(pending.driver_email)
            status_info = {'type': 'pending', 'driver_name': (driver.name if driver else pending.driver_email),
                           'timestamp': format_datetime_npt(pending.timestamp),
                           'message': f"Request to {driver.name if driver else pending.driver_email} is pending..."}
        else:
            last_inactive = RideRequest.query.filter(RideRequest.user_email==user.email, RideRequest.status.in_(['rejected','superseded'])).order_by(RideRequest.timestamp.desc()).first()
            if last_inactive:
                driver = Driver.query.get(last_inactive.driver_email)
                msg = f"Previous request to {driver.name if driver else last_inactive.driver_email} was {last_inactive.status}."
                if last_inactive.status == 'superseded': msg = "Previous active request was superseded."
                status_info = {'type':last_inactive.status, 'driver_name':(driver.name if driver else last_inactive.driver_email),
                               'timestamp':format_datetime_npt(last_inactive.timestamp), 'message':msg}
    response = make_response(render_template('user_dashboard.html', user=user, drivers_for_js=drivers_js, 
                           coords=coordinates, current_ride_status=status_info, graph_for_js=graph))
    return add_no_cache_to_response(response)

@app.route('/user-home')
@login_required_user
def user_home(): 
    response = make_response(render_template('user_home.html', user=User.query.get(session.get('user'))))
    return add_no_cache_to_response(response)

@app.route('/driver-home')
@login_required_driver
def driver_home(): 
    response = make_response(render_template('driver_home.html', driver=Driver.query.get(session.get('driver'))))
    return add_no_cache_to_response(response)

@app.route('/user-about')
@login_required_user
def user_about(): 
    response = make_response(render_template('user_about.html'))
    return add_no_cache_to_response(response)

@app.route('/driver-about')
@login_required_driver
def driver_about(): 
    response = make_response(render_template('driver_about.html'))
    return add_no_cache_to_response(response)

@app.route('/user-history') 
@login_required_user
def user_history():
    reqs_db = RideRequest.query.filter_by(user_email=session['user']).order_by(RideRequest.timestamp.desc()).all()
    s_reqs = [{'driver_name': (Driver.query.get(r.driver_email).name or r.driver_email if Driver.query.get(r.driver_email) else "N/A"), 
               'status': r.status, 'timestamp': format_datetime_npt(r.timestamp)} for r in reqs_db]
    response = make_response(render_template('user_history.html', requests=s_reqs))
    return add_no_cache_to_response(response)

@app.route('/driver-history')
@login_required_driver
def driver_history():
    reqs_db = RideRequest.query.filter_by(driver_email=session['driver']).order_by(RideRequest.timestamp.desc()).all()
    s_reqs = [{'user_name': (User.query.get(r.user_email).name or r.user_email if User.query.get(r.user_email) else "N/A"), 
               'status': r.status, 'timestamp': format_datetime_npt(r.timestamp)} for r in reqs_db]
    response = make_response(render_template('driver_history.html', requests=s_reqs))
    return add_no_cache_to_response(response)

@app.route('/logout')
def logout(): 
    session.clear()
    response = make_response(redirect(url_for('login')))
    return add_no_cache_to_response(response) # Also apply to the redirect itself

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)