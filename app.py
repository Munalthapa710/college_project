from flask import Flask, render_template, request, redirect, session, jsonify, make_response, url_for, flash 
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import pytz
import re
from functools import wraps 
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    form_data_to_pass = {} 
    if request.method == 'POST':
        role = request.form.get('role')
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '') 
        confirm_password = request.form.get('confirm_password', '')

        form_data_to_pass = request.form.to_dict()
        errors = []

        # --- Enhanced Validation Checks ---
        if not role:
            errors.append("Role selection is required.")
        if not name:
            errors.append("Full Name is required.")
        elif len(name) < 2 or len(name) > 100:
            errors.append("Full Name must be between 2 and 100 characters.")

        if not email:
            errors.append("Email is required.")
        # Basic regex for email validation (not foolproof, but better)
        elif not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            errors.append("Invalid email format.")
        
        if not phone:
            errors.append("Phone number is required.")
        # Basic regex for phone: allows optional +, digits, hyphens, spaces, parentheses, min 7 digits
        elif not re.match(r"^\+?[\d\s\-()]{7,20}$", phone):
            errors.append("Invalid phone number format (e.g., +1234567890, 123-456-7890). Must be 7-20 digits/allowed characters.")
        
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        # Example: Add password complexity check (e.g., one uppercase, one number)
        # elif not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        #     errors.append("Password must include at least one uppercase letter and one number.")
        
        if password != confirm_password:
            if password: 
                 errors.append("Passwords do not match.")
        
        vehicle = "" 
        node_from_form = "" 

        if role == 'driver':
            vehicle = request.form.get('vehicle', '').strip()
            node_from_form = request.form.get('node') 
            if not vehicle:
                errors.append("Vehicle information is required for drivers.")
            elif len(vehicle) < 2 or len(vehicle) > 50:
                errors.append("Vehicle information must be between 2 and 50 characters.")

            if not node_from_form:
                errors.append("Driver's initial location node selection is required.")
            elif node_from_form not in coordinates:
                 errors.append(f"Invalid location node ('{node_from_form}') selected. Please choose from the list.")

        if not errors: 
            if role == 'driver':
                if Driver.query.filter_by(email=email).first():
                    errors.append(f"A driver account with the email '{email}' already exists.")
            else: 
                if User.query.filter_by(email=email).first():
                    errors.append(f"A user account with the email '{email}' already exists.")
        
        if errors:
            for error_msg in errors:
                flash(error_msg, 'error')
            return render_template('register.html', 
                                   nodes=coordinates.keys(), 
                                   form_data=form_data_to_pass)

        
        if role == 'driver':
            new_entity = Driver(email=email, name=name, phone=phone, password=password, vehicle=vehicle, node=node_from_form) # Use hashed_password
        else: 
            new_entity = User(email=email, name=name, phone=phone, password=password, latitude=None, longitude=None) # Use hashed_password
        
        db.session.add(new_entity)
        try: 
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e: 
            db.session.rollback()
            print(f"DATABASE COMMIT ERROR during registration: {e}")
            flash(f"An unexpected error occurred: {str(e)[:100]}...", 'error') # Show a generic or truncated error
            return render_template('register.html', nodes=coordinates.keys(), form_data=form_data_to_pass)

    return render_template('register.html', nodes=coordinates.keys(), form_data={})

@app.route('/login', methods=['GET', 'POST'])
def login():
    form_data_to_pass = {} # Initialize for GET request
    if request.method == 'POST':
        role = request.form.get('role')
        # Use .get with a default empty string and .strip() for safety
        email = request.form.get('username', '').strip().lower() 
        password = request.form.get('password', '')

        # Store submitted data to pass back to template if login fails
        form_data_to_pass = request.form.to_dict() 

        # Basic validation for empty fields
        if not email or not password or not role:
            flash("All fields (Email, Password, Role) are required.", "error")
            return render_template('login.html', form_data=form_data_to_pass)

        login_successful = False
        if role == 'driver':
            driver = Driver.query.filter_by(email=email).first() # Query by normalized email
            # IMPORTANT: In a real app, compare HASHED passwords
            # if driver and check_password_hash(driver.password, password):
            if driver and driver.password == password: 
                session['driver'] = driver.email
                flash(f'Welcome back, {driver.name}!', 'success')
                login_successful = True
                # Check for 'next' URL parameter if you implement redirection after login
                # next_url = request.args.get('next')
                # return redirect(next_url or url_for('dashboard'))
                return redirect(url_for('dashboard'))
        elif role == 'user':
            user = User.query.filter_by(email=email).first() # Query by normalized email
            # IMPORTANT: In a real app, compare HASHED passwords
            # if user and check_password_hash(user.password, password):
            if user and user.password == password: 
                session['user'] = user.email
                flash(f'Welcome back, {user.name}!', 'success')
                login_successful = True
                # next_url = request.args.get('next')
                # return redirect(next_url or url_for('user_dashboard'))
                return redirect(url_for('user_dashboard'))
        
        # If login was not successful after checking both roles
        if not login_successful:
            flash('Invalid email, password, or role. Please try again.', 'error')
            # Re-render the login page with an error message and pre-filled email (but not password)
            form_data_to_pass.pop('password', None) # Don't send password back
            return render_template('login.html', form_data=form_data_to_pass)
            
    # For GET request, render the login page
    return render_template('login.html', form_data=form_data_to_pass)
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
    # No need to check 'user' in session again due to @login_required_user
    data = request.get_json()
    if not data: 
        return jsonify({'error': 'Invalid request: No JSON data received', 'success': False}), 400
    
    user_closest_node = data.get('user_closest_node')
    selected_vehicle_type = data.get('vehicle_type', "").strip().lower() # Get selected vehicle type, lowercase for case-insensitive compare

    if not user_closest_node or user_closest_node not in graph or user_closest_node not in coordinates:
        return jsonify({'error': 'Invalid or missing user_closest_node for Dijkstra.', 'success': False}), 400
    
    # Start with drivers who have a valid node that is also present in the graph definition
    driver_query = Driver.query.filter(Driver.node.isnot(None), Driver.node.in_(graph.keys()))

    # Further filter by vehicle type if one is selected
    if selected_vehicle_type:
        # Using SQLAlchemy's func.lower for case-insensitive comparison on the database side if possible
        # For SQLite, ilike is often case-insensitive by default for ASCII, but explicit lower is safer across DBs.
        driver_query = driver_query.filter(db.func.lower(Driver.vehicle).contains(selected_vehicle_type))
        # If you need exact match (case-insensitive):
        # driver_query = driver_query.filter(db.func.lower(Driver.vehicle) == selected_vehicle_type)
    
    available_drivers = driver_query.all()
    
    nearest_driver_info = None
    min_distance = float('inf')

    if not available_drivers: 
        message = f"No '{selected_vehicle_type if selected_vehicle_type else 'available'}' drivers found matching criteria."
        if not selected_vehicle_type: message = "No drivers currently available or their nodes are not in routing graph."
        return jsonify({'message': message, 'success': True, 'nearest_driver': None})

    for driver in available_drivers:
        # driver.node is already confirmed to be in graph by the query filter
        distance = dijkstra(graph, user_closest_node, driver.node)
        print(f"Dijkstra: UserNode '{user_closest_node}' to DriverNode '{driver.node}' (Driver: {driver.name}, Vehicle: {driver.vehicle}): dist {distance}")

        if distance < min_distance: # Check if distance is not infinity
            min_distance = distance
            path = shortest_path(graph, user_closest_node, driver.node)
            if path: # A path was found
                nearest_driver_info = {
                    'email': driver.email, 
                    'name': driver.name, 
                    'vehicle': driver.vehicle, 
                    'node': driver.node, 
                    'graph_distance': round(min_distance, 2) if min_distance != float('inf') else "Unreachable", 
                    'path_nodes': path 
                }
            else: # Should not happen if distance is not inf, but a safeguard
                 # If dijkstra returned a finite distance but shortest_path is empty, it indicates an issue
                 # in how shortest_path reconstructs or if the graph has inconsistencies.
                 # For now, if no path array, consider it not the best option.
                if min_distance != float('inf'): # Only print warning if distance was finite
                    print(f"Warning: Dijkstra found distance {min_distance} but shortest_path returned no path for {user_closest_node} to {driver.node}")
                min_distance = float('inf') # Effectively disqualifies this driver if path not found
                
    if nearest_driver_info: 
        return jsonify({'success': True, 'nearest_driver': nearest_driver_info})
    
    message = f"No reachable '{selected_vehicle_type if selected_vehicle_type else 'drivers'}' found via network path."
    if not selected_vehicle_type and not available_drivers: message = "No drivers found on the network."

    return jsonify({'message': message, 'success': True, 'nearest_driver': None})

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
    if not user: # Should be caught by decorator, but good for direct calls
        session.pop('user', None)
        flash('User session not found, please log in again.', 'error')
        return redirect(url_for('login'))

    # Get list of drivers with valid nodes for "Find Nearest" functionality
    drivers_with_nodes = Driver.query.filter(Driver.node.isnot(None)).all()
    driver_list_for_js = [
        {'email': d.email, 'name': d.name, 'vehicle': d.vehicle, 'node': d.node}
        for d in drivers_with_nodes if d.node in coordinates # Ensure node is in your defined coordinates
    ]
    
    current_ride_status_info = None
    # --- Logic to determine current_ride_status_info ---
    accepted_ride_db = RideRequest.query.filter_by(user_email=user.email, status='accepted').order_by(RideRequest.timestamp.desc()).first()

    if accepted_ride_db:
        driver_obj = Driver.query.get(accepted_ride_db.driver_email)
        # Ensure all necessary location data is present for an accepted ride
        if driver_obj and driver_obj.node and driver_obj.node in coordinates and \
           accepted_ride_db.user_latitude_at_request is not None and \
           accepted_ride_db.user_longitude_at_request is not None:
            current_ride_status_info = {
                'type': 'accepted', 
                'driver_name': driver_obj.name,
                'driver_node': driver_obj.node, 
                'user_latitude_for_route': accepted_ride_db.user_latitude_at_request,
                'user_longitude_for_route': accepted_ride_db.user_longitude_at_request,
                'timestamp': format_datetime_npt(accepted_ride_db.timestamp),
                'message': f"Your ride with {driver_obj.name} is confirmed! Driver is en route."
            }
        else:
            print(f"Warning (User Dashboard): Accepted ride ID {accepted_ride_db.id} has invalid location data. Driver Node: {driver_obj.node if driver_obj else 'N/A'}, User Lat: {accepted_ride_db.user_latitude_at_request}, User Lng: {accepted_ride_db.user_longitude_at_request}")
            current_ride_status_info = {'type': 'error', 'message': 'Error displaying accepted ride details (location data issue).', 'timestamp': format_datetime_npt(datetime.now(timezone.utc))}
    else:
        pending_ride_db = RideRequest.query.filter_by(user_email=user.email, status='Pending').order_by(RideRequest.timestamp.desc()).first()
        if pending_ride_db:
            driver_obj = Driver.query.get(pending_ride_db.driver_email)
            driver_name_pending = driver_obj.name if driver_obj else pending_ride_db.driver_email
            current_ride_status_info = {
                'type': 'pending', 
                'driver_name': driver_name_pending,
                'timestamp': format_datetime_npt(pending_ride_db.timestamp),
                'message': f"Your request to {driver_name_pending} is pending..."
            }
        else:
            last_inactive_ride_db = RideRequest.query.filter(
                RideRequest.user_email == user.email, 
                RideRequest.status.in_(['rejected','superseded'])
            ).order_by(RideRequest.timestamp.desc()).first()
            if last_inactive_ride_db:
                driver_obj = Driver.query.get(last_inactive_ride_db.driver_email)
                driver_name_inactive = driver_obj.name if driver_obj else last_inactive_ride_db.driver_email
                msg = f"Previous request to {driver_name_inactive} was {last_inactive_ride_db.status}."
                if last_inactive_ride_db.status == 'superseded': 
                    msg = "Your previous active request was superseded by a new one."
                current_ride_status_info = {
                    'type': last_inactive_ride_db.status, 
                    'driver_name': driver_name_inactive,
                    'timestamp': format_datetime_npt(last_inactive_ride_db.timestamp), 
                    'message': msg
                }
    # --- END Logic to determine current_ride_status_info ---

    # --- Get unique vehicle types from Driver table for the dropdown ---
    vehicle_types_query = db.session.query(Driver.vehicle).filter(Driver.vehicle.isnot(None), Driver.vehicle != '').distinct().all()
    # vehicle_types_query will be a list of tuples, e.g., [('Ambulance',), ('Fire Truck',)]
    # Flatten it to a simple list of strings, handling None values or empty strings
    vehicle_types = sorted([vt[0] for vt in vehicle_types_query if vt[0]]) 
    print(f"[User Dashboard] Unique Vehicle Types Found: {vehicle_types}")
    # --- END Get unique vehicle types ---

    response = make_response(render_template('user_dashboard.html', 
                                                user=user, 
                                                drivers_for_js=driver_list_for_js, 
                                                coords=coordinates, # For driver node locations
                                                current_ride_status=current_ride_status_info, 
                                                graph_for_js=graph, # For Dijkstra path visualization
                                                vehicle_types=vehicle_types)) # Pass to template
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
@login_required_user # Assuming you have this decorator
def user_about(): 
    user = User.query.get(session.get('user')) # Fetch the current user
    response = make_response(render_template('user_about.html', user=user)) # Pass user to template
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
@app.route('/your-driver-route')
@login_required_driver
def your_driver_route_function():
    driver = Driver.query.get(session.get('driver'))
    if not driver: # Add this check just in case, though decorator should catch session issues
        flash("Driver information not found for this session.", "error")
        session.clear()
        return redirect(url_for('login'))
    
    # ... any other logic for this specific route ...

    # Ensure 'driver' is passed here
    response = make_response(render_template('the_driver_template.html', driver=driver ))
    return add_no_cache_to_response(response)
@app.route('/logout')
def logout(): 
    session.clear()
    response = make_response(redirect(url_for('login')))
    return add_no_cache_to_response(response) # Also apply to the redirect itself

@app.route('/edit-user-profile', methods=['GET', 'POST'])
@login_required_user
def edit_user_profile():
    user = User.query.get(session['user'])
    if not user: # Should be caught by decorator, but good practice
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get data from form
        new_name = request.form.get('name', '').strip()
        new_phone = request.form.get('phone', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Update name and phone if provided and different
        if new_name and new_name != user.name:
            user.name = new_name
            flash('Name updated successfully.', 'success')
        
        if new_phone and new_phone != user.phone:
            # TODO: Add phone number validation if needed
            user.phone = new_phone
            flash('Phone number updated successfully.', 'success')

        # Update password if new password is provided and matches confirmation
        if new_password:
            if new_password == confirm_password:
                # In a real app, you would HASH this new_password before saving
                # For example: user.password = generate_password_hash(new_password)
                user.password = new_password 
                flash('Password updated successfully.', 'success')
            else:
                flash('New passwords do not match. Password not updated.', 'error')
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error updating user profile: {e}")
            flash('Error updating profile. Please try again.', 'error')
        
        return redirect(url_for('edit_user_profile')) # Redirect back to profile page to see changes/errors

    response = make_response(render_template('edit_user_profile.html', user=user, title="Edit Your Profile"))
    return add_no_cache_to_response(response)


@app.route('/edit-driver-profile', methods=['GET', 'POST'])
@login_required_driver
def edit_driver_profile():
    driver = Driver.query.get(session['driver'])
    if not driver:
        flash('Driver not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_name = request.form.get('name', '').strip()
        new_phone = request.form.get('phone', '').strip()
        new_vehicle = request.form.get('vehicle', '').strip()
        # Driver node changes might need more complex logic/validation if it impacts active operations
        # For now, let's assume node is not changed here, or if it is, it's a valid node from `coordinates`.
        new_node = request.form.get('node') 
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if new_name and new_name != driver.name:
            driver.name = new_name
            flash('Name updated.', 'success')
        
        if new_phone and new_phone != driver.phone:
            driver.phone = new_phone
            flash('Phone updated.', 'success')

        if new_vehicle and new_vehicle != driver.vehicle:
            driver.vehicle = new_vehicle
            flash('Vehicle updated.', 'success')
        
        if new_node and new_node != driver.node and new_node in coordinates:
            driver.node = new_node
            flash('Location Node updated.', 'success')
        elif new_node and new_node != driver.node and new_node not in coordinates:
            flash('Invalid Location Node selected. Node not updated.', 'error')


        if new_password:
            if new_password == confirm_password:
                driver.password = new_password # HASH this in real app
                flash('Password updated.', 'success')
            else:
                flash('New passwords do not match. Password not updated.', 'error')
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error updating driver profile: {e}")
            flash('Error updating profile.', 'error')
        
        return redirect(url_for('edit_driver_profile'))

    response = make_response(render_template('edit_driver_profile.html', driver=driver, nodes=coordinates.keys(), title="Edit Driver Profile"))
    return add_no_cache_to_response(response)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)