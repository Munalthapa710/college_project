from flask import Flask, render_template, request, redirect, session, jsonify, make_response, url_for, flash 
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_socketio import SocketIO, emit, join_room, leave_room
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

# Initialize SocketIO AFTER app configuration
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
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

        # Validation Checks ---
        if not role:
            errors.append("Role selection is required.")
        if not name:
            errors.append("Full Name is required.")
        elif len(name) < 2 or len(name) > 100:
            errors.append("Full Name must be between 2 and 100 characters.")

        if not email:
            errors.append("Email is required.")
        # for email validation 
        elif not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            errors.append("Invalid email format.")
        
        if not phone:
            errors.append("Phone number is required.")
        #for phone num
        elif not re.match(r"^\+?[\d\s\-()]{7,20}$", phone):
            errors.append("Invalid phone number format (e.g., +1234567890, 123-456-7890). Must be 7-20 digits/allowed characters.")
        
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        
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
            new_entity = Driver(email=email, name=name, phone=phone, password=password, vehicle=vehicle, node=node_from_form) 
        else: 
            new_entity = User(email=email, name=name, phone=phone, password=password, latitude=None, longitude=None) 
        db.session.add(new_entity)
        try: 
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e: 
            db.session.rollback()
            print(f"DATABASE COMMIT ERROR during registration: {e}")
            flash(f"An unexpected error occurred: {str(e)[:100]}...", 'error') 
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

        if not email or not password or not role:
            flash("All fields (Email, Password, Role) are required.", "error")
            return render_template('login.html', form_data=form_data_to_pass)

        login_successful = False
        if role == 'driver':
            driver = Driver.query.filter_by(email=email).first() # Query by normalized email
            if driver and driver.password == password: 
                session['driver'] = driver.email
                flash(f'Welcome back, {driver.name}!', 'success')
                login_successful = True
                return redirect(url_for('dashboard'))
        elif role == 'user':
            user = User.query.filter_by(email=email).first() # Query by normalized email
            if user and user.password == password: 
                session['user'] = user.email
                flash(f'Welcome back, {user.name}!', 'success')
                login_successful = True
                return redirect(url_for('user_dashboard'))
        
        # If login was not successful after checking both roles
        if not login_successful:
            flash('Invalid email, password, or role. Please try again.', 'error')
            form_data_to_pass.pop('password', None)  # Re-render the login page with an error message and pre-filled email (but not password)
            return render_template('login.html', form_data=form_data_to_pass)
            
    # For GET request, render the login page
    return render_template('login.html', form_data=form_data_to_pass)

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
    data = request.get_json()
    if not data: 
        return jsonify({'error': 'Invalid request: No JSON data received', 'success': False}), 400
    
    user_closest_node = data.get('user_closest_node')
    selected_vehicle_type = data.get('vehicle_type', "").strip().lower() # Get selected vehicle type, lowercase for case-insensitive compare

    if not user_closest_node or user_closest_node not in graph or user_closest_node not in coordinates:
        return jsonify({'error': 'Invalid or missing user_closest_node for Dijkstra.', 'success': False}), 400
    
    driver_query = Driver.query.filter(Driver.node.isnot(None), Driver.node.in_(graph.keys()))

    # Further filter by vehicle type if one is selected
    if selected_vehicle_type:
        driver_query = driver_query.filter(db.func.lower(Driver.vehicle).contains(selected_vehicle_type))
       
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
            else:
                if min_distance != float('inf'): 
                    print(f"Warning: Dijkstra found distance {min_distance} but shortest_path returned no path for {user_closest_node} to {driver.node}")
                min_distance = float('inf') 
                
    if nearest_driver_info: 
        return jsonify({'success': True, 'nearest_driver': nearest_driver_info})
    message = f"No reachable '{selected_vehicle_type if selected_vehicle_type else 'drivers'}' found via network path."
    if not selected_vehicle_type and not available_drivers: message = "No drivers found on the network."
    return jsonify({'message': message, 'success': True, 'nearest_driver': None})

@app.route('/request-ride', methods=['POST'])
@login_required_user
def request_ride():
    if 'user' not in session: 
        return jsonify({'message': 'Not logged in', 'success': False}), 403
    
    data = request.get_json()
    if not data:
         return jsonify({'message': 'Invalid request: No JSON data received', 'success': False}), 400
    
    driver_email = data.get('driver_email')
    if not driver_email:
        return jsonify({'message': 'Driver email missing from request', 'success': False}), 400
        
    user_email = session['user']

    RideRequest.query.filter(
        RideRequest.user_email == user_email, 
        RideRequest.status.in_(['Pending', 'accepted'])
    ).update({'status': 'superseded'}, synchronize_session='fetch')
   
    requesting_user = User.query.get(user_email)
    if not requesting_user: 
        return jsonify({'message': 'Requesting user not found in database.', 'success': False}), 404
    
    if requesting_user.latitude is None or requesting_user.longitude is None:
        return jsonify({'message': 'Your precise location is not set. Please click the map to set your location before requesting a ride.', 'success': False}), 400

    new_ride = RideRequest(
        user_email=user_email,
        driver_email=driver_email,
        user_latitude_at_request=requesting_user.latitude,
        user_longitude_at_request=requesting_user.longitude,
        status='Pending'
    )
    db.session.add(new_ride)
    
    try:
        db.session.commit()
        
        # --- SOCKET.IO EMIT for new ride request ---
        driver_target_email_for_room = new_ride.driver_email # The driver's email is the room name
        
        ride_data_for_driver_socket = {
            'id': new_ride.id,
            'user_email': new_ride.user_email,
            'user_name': requesting_user.name or "A User",
            'user_latitude': new_ride.user_latitude_at_request,
            'user_longitude': new_ride.user_longitude_at_request,
            'timestamp': format_datetime_npt(new_ride.timestamp), # Send formatted time
            'status': new_ride.status
        }
        socketio.emit('new_ride_request', ride_data_for_driver_socket, room=driver_target_email_for_room)
        print(f"DEBUG: Emitted 'new_ride_request' to driver room: {driver_target_email_for_room} for ride {new_ride.id}")
        # --- END SOCKET.IO EMIT ---

        return jsonify({'message': f'Ride requested successfully from driver {new_ride.driver_email}!', 'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"DATABASE ERROR during /request-ride commit or emit: {e}")
        return jsonify({'message': 'Error processing your ride request. Please try again.', 'success': False}), 500

@app.route('/accept-request', methods=['POST'])
@login_required_driver
def accept_request():
    data = request.get_json()
    if not data: return jsonify({'error': 'Invalid request', 'success': False}), 400
    req_id = data.get('id')
    if not req_id: return jsonify({'error': 'Request ID missing', 'success': False}), 400
    
    req = RideRequest.query.get(req_id)
    if not req: return jsonify({'error': 'Request not found', 'success': False}), 404
    if req.driver_email != session['driver']: return jsonify({'error': 'Unauthorized', 'success': False}), 403
    if req.status != 'Pending': return jsonify({'error': f'Request is not pending (status: {req.status})', 'success': False}), 400
    
    if req.user_latitude_at_request is None or req.user_longitude_at_request is None:
        return jsonify({'error': 'Cannot accept: User location (lat/lng) for this specific request is missing.', 'success': False}), 400
    
    try:
        req.status = 'accepted'
        db.session.commit()
        # --- SOCKET.IO EMIT for ride accepted ---
        user_to_notify_email = req.user_email
        driver_accepting = Driver.query.get(session['driver']) # Get current driver object
        acceptance_data = {
            'ride_id': req.id,
            'driver_name': driver_accepting.name if driver_accepting else "Your Driver",
            'driver_node': driver_accepting.node if driver_accepting else None, # User map needs this
            'driver_vehicle': driver_accepting.vehicle if driver_accepting else "N/A",
            'user_latitude_for_route': req.user_latitude_at_request, # Send user's loc for consistency
            'user_longitude_for_route': req.user_longitude_at_request,
            'message': f"Your ride request (ID: {req.id}) has been accepted by {driver_accepting.name if driver_accepting else 'your driver'}!"
        }
        socketio.emit('ride_accepted', acceptance_data, room=user_to_notify_email)
        print(f"DEBUG: Emitted 'ride_accepted' to user room: {user_to_notify_email} for ride {req.id}")
        # --- END SOCKET.IO EMIT ---
        return jsonify({'success': True, 'message': 'Ride accepted'}), 200
    except Exception as e: 
        db.session.rollback()
        print(f"DATABASE ERROR during /accept-request commit or emit: {e}")
        return jsonify({'error': 'Database error or problem emitting notification while accepting request.', 'success': False}), 500

@app.route('/reject-request', methods=['POST'])
@login_required_driver
def reject_request():
    data = request.get_json()
    if not data: return jsonify({'error': 'Invalid request', 'success': False}), 400
    req_id = data.get('id')
    if not req_id: return jsonify({'error': 'Request ID missing', 'success': False}), 400
    req = RideRequest.query.get(req_id)
    if not req: return jsonify({'error': 'Request not found', 'success': False}), 404
    if req.driver_email != session['driver']: return jsonify({'error': 'Unauthorized', 'success': False}), 403
    if req.status != 'Pending':
        return jsonify({'error': f'Request is not pending (status: {req.status})', 'success': False}), 400
    
    try:
        req.status = 'rejected'
        db.session.commit()

        # --- SOCKET.IO EMIT for ride rejected ---
        user_to_notify_email = req.user_email
        driver_rejecting = Driver.query.get(session['driver'])
        rejection_data = {
            'ride_id': req.id,
            'driver_name': driver_rejecting.name if driver_rejecting else "A driver",
            'message': f"Your ride request (ID: {req.id}) was rejected by {driver_rejecting.name if driver_rejecting else 'a driver'}."
        }
        socketio.emit('ride_rejected', rejection_data, room=user_to_notify_email)
        print(f"DEBUG: Emitted 'ride_rejected' to user room: {user_to_notify_email} for ride {req.id}")
        # --- END SOCKET.IO EMIT ---
        return jsonify({'success': True, 'message': 'Ride rejected'}), 200
    except Exception as e: 
        db.session.rollback()
        print(f"DATABASE ERROR during /reject-request commit or emit: {e}")
        return jsonify({'error': 'Database error or problem emitting notification while rejecting request.', 'success': False}), 500

@app.route('/complete-ride', methods=['POST'])
@login_required_driver
def complete_ride():
    data = request.get_json()
    if not data: return jsonify({'error': 'Invalid request', 'success': False}), 400
        
    ride_id = data.get('ride_id')
    if not ride_id:
        return jsonify({'error': 'Ride ID missing in request', 'success': False}), 400
    ride = RideRequest.query.get(ride_id)
    if not ride:
        return jsonify({'error': 'Ride not found in database', 'success': False}), 404
    if ride.driver_email != session['driver']:
        return jsonify({'error': 'Unauthorized: You cannot complete this ride', 'success': False}), 403
    if ride.status != 'accepted': 
        print(f"Warning: Attempting to complete ride ID {ride.id} which was not in 'accepted' state (current status: {ride.status}).")       
    
    try:
        ride.status = 'completed'
        db.session.commit()

        # --- SOCKET.IO EMIT for ride completed ---
        user_to_notify_email = ride.user_email
        driver_completing = Driver.query.get(session['driver'])
        completion_data = {
            'ride_id': ride.id,
            'driver_name': driver_completing.name if driver_completing else "Your driver",
            'message': f"Your ride (ID: {ride.id}) with {driver_completing.name if driver_completing else 'your driver'} has been completed. Thank you!"
        }
        socketio.emit('ride_completed', completion_data, room=user_to_notify_email)
        print(f"DEBUG: Emitted 'ride_completed' to user room: {user_to_notify_email} for ride {ride.id}")
        # --- END SOCKET.IO EMIT ---
        return jsonify({'message': 'Ride marked as completed successfully!', 'success': True}), 200
    except Exception as e: 
        db.session.rollback()
        print(f"DATABASE ERROR during /complete-ride commit or emit: {e}")
        return jsonify({'error': 'Database error or problem emitting notification while completing ride.', 'success': False}), 500

# --- HTML Rendering Routes with Explicit No-Cache Headers ---
@app.route('/dashboard') 
@login_required_driver
def dashboard():
    driver = Driver.query.get(session['driver'])
    
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
    if not user: 
        session.pop('user', None)
        flash('User session not found, please log in again.', 'error')
        return redirect(url_for('login'))

    # Get list of drivers with valid nodes for "Find Nearest" functionality
    drivers_with_nodes = Driver.query.filter(Driver.node.isnot(None)).all()
    driver_list_for_js = [
        {'email': d.email, 'name': d.name, 'vehicle': d.vehicle, 'node': d.node}
        for d in drivers_with_nodes if d.node in coordinates # Ensure node is in your defined coordinates
    ]
    
    current_ride_status_info = None #Ride status
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
                'message': f"Your ride with {driver_obj.name} is confirmed! Driver is on the way."
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
@login_required_user 
def user_about(): 
    user = User.query.get(session.get('user')) 
    response = make_response(render_template('user_about.html', user=user)) 
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
    if not driver: 
        flash("Driver information not found for this session.", "error")
        session.clear()
        return redirect(url_for('login'))
    
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
    if not user: 
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
            # Add phone number validation if needed
            user.phone = new_phone
            flash('Phone number updated successfully.', 'success')

        # Update password if new password is provided and matches confirmation
        if new_password:
            if new_password == confirm_password:
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
        
        return redirect(url_for('edit_user_profile')) 
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
                driver.password = new_password 
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

# --- SOCKET.IO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    # This event fires when a client's browser successfully establishes a WebSocket connection.
    # The `request.sid` is a unique session ID for that WebSocket connection.
    print(f"Client connected: {request.sid}")

@socketio.on('join') 
def on_join(data): # 'data' will be the JSON object sent by the client
    email_to_join = data.get('email')
    if email_to_join:
        join_room(email_to_join) # The client joins a room named after their email.
        print(f"Client {request.sid} with email {email_to_join} joined room '{email_to_join}'.")
        emit('status_update', {'msg': f'Successfully joined room {email_to_join}.'}, room=request.sid) 
    else:
        print(f"Client {request.sid} attempted to join a room without providing an email.")

@socketio.on('disconnect')
def handle_disconnect():
    # This event fires when a client disconnects.
    print(f"Client disconnected: {request.sid}")
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("Starting Flask-SocketIO server with eventlet...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=True) 