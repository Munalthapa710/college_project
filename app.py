from flask import Flask, render_template, request, redirect, session, jsonify, make_response, url_for, flash 
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_socketio import SocketIO, emit, join_room
import pytz
import re
from functools import wraps 
from dijkstra import dijkstra, shortest_path 
from graph_with_coords import graph, coordinates ,emergency_services
import os
from werkzeug.security import generate_password_hash, check_password_hash 
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import timedelta

app = Flask(__name__) 
app.secret_key = os.urandom(24).hex() 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.instance_path, exist_ok=True)#database file creating 
scheduler = BackgroundScheduler()
scheduler.start()
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*") # initilize socket 
db = SQLAlchemy(app)

#to handle time zone (nepal time)
NPT = pytz.timezone('Asia/Kathmandu')
def format_datetime_npt(dt_utc):
    if dt_utc is None: return "N/A"
    if dt_utc.tzinfo is None or dt_utc.tzinfo.utcoffset(dt_utc) is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    else:
        dt_utc = dt_utc.astimezone(timezone.utc)
    dt_npt = dt_utc.astimezone(NPT)
    return dt_npt.strftime('%Y-%m-%d %H:%M NPT')

# Database 
class Admin(db.Model):
    __tablename__ = 'admin'
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(256)) # Increased length for hash

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
    password = db.Column(db.String(256)) # Increased length for hash
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

class Driver(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(256)) # Increased length for hash
    vehicle = db.Column(db.String(50))
    node = db.Column(db.String(10), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

# cli command for admin #ACT AS DECORATOR
@app.cli.command("create-admin")
def create_admin_command():
    """Creates the initial admin user for the application."""
    if Admin.query.first():
        print("An admin user already exists. Aborting.")
        return
    
    #configuting admin in here
    admin_email = "admin@gmail.com"
    admin_name = "System Administrator"
    admin_password = "Admin123"  

    # Hash the password for security
    hashed_password = generate_password_hash(admin_password)

    new_admin = Admin(
        email=admin_email,
        name=admin_name,
        password=hashed_password
    )

    db.session.add(new_admin)
    db.session.commit()
    
    print(f"Admin user '{admin_name}' with email '{admin_email}' created successfully.")
    print("You can now log in with this account using the 'Admin' role.")
    
@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    db.create_all()
    print("Initialized the database.")

# decorators for Authentication
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

def login_required_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            flash("Admin access required.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# for authenticated HTML pages.
def add_no_cache_to_response(response):
    """Adds no-cache headers to a given Flask response object."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def check_and_reroute_ride(ride_id, user_email, excluded_drivers=None):
    """
    A background job to check a ride request's status after a timeout.
    If it's still pending, it finds the next nearest driver and re-assigns,
    maintaining a list of drivers who have already timed out.
    """
    # Initialize the exclusion list if this is the first timeout in a chain.
    if excluded_drivers is None:
        excluded_drivers = []
        
    print(f"[JOB] Running check for ride_id: {ride_id}. Drivers already excluded: {excluded_drivers}")

    with app.app_context(): # Jobs run outside Flask's normal context, so this is required.
        # Find the specific ride request that this job is for.
        original_request = db.session.get(RideRequest, ride_id)

        # 1. First, check if the ride is still 'Pending'. If it was accepted, rejected,
        #    or cancelled, the job has nothing to do and should simply finish.
        if not original_request or original_request.status != 'Pending':
            print(f"[JOB] Ride {ride_id} is no longer pending. Status: {original_request.status if original_request else 'Not Found'}. Job finished.")
            return

        print(f"[JOB] Ride {ride_id} timed out. Adding {original_request.driver_email} to exclusion list.")
        
        # 2. Mark the current request as 'timed_out' and add its driver to our growing list of exclusions.
        original_request.status = 'timed_out'
        if original_request.driver_email not in excluded_drivers:
            excluded_drivers.append(original_request.driver_email)
        
        # 3. Find the next nearest driver, ensuring we use the CUMULATIVE exclusion list.
        user = User.query.get(user_email)
        if not user or user.latitude is None:
            print("[JOB] User or user location not found. Cannot find next driver.")
            db.session.commit() # Commit the 'timed_out' status before exiting.
            return
            
        # The database query now uses the full list of excluded drivers.
        all_available_drivers = Driver.query.filter(
            Driver.is_approved == True,
            Driver.node.isnot(None),
            Driver.email.notin_(excluded_drivers) # Use .notin_ with the entire list.
        ).all()

        if not all_available_drivers:
            print("[JOB] No other drivers are available after applying exclusions.")
            socketio.emit('ride_timeout_no_drivers', {'message': 'Your request timed out and no other drivers are available.'}, room=user_email)
            db.session.commit()
            return

        # Find the user's closest node to run Dijkstra from.
        user_latlng = (user.latitude, user.longitude)
        closest_node_key = None
        min_dist = float('inf')
        for node, coord in coordinates.items():
            dist = ( (user_latlng[0]-coord[0])**2 + (user_latlng[1]-coord[1])**2 )**0.5
            if dist < min_dist:
                min_dist = dist
                closest_node_key = node
        
        if not closest_node_key:
            print("[JOB] Could not determine user's closest graph node.")
            db.session.commit()
            return

        # Run Dijkstra's for all remaining available drivers to find the best one.
        next_driver_obj = None
        min_path_dist = float('inf')
        for driver in all_available_drivers:
            if driver.node in graph:
                path_dist = dijkstra(graph, closest_node_key, driver.node)
                if path_dist < min_path_dist:
                    min_path_dist = path_dist
                    next_driver_obj = driver

        if not next_driver_obj:
            print("[JOB] Other drivers were found, but none are reachable on the network graph.")
            socketio.emit('ride_timeout_no_drivers', {'message': 'Your request timed out and no other reachable drivers were found.'}, room=user_email)
            db.session.commit()
            return

        # 4. A new best driver was found. Create a new ride request for them.
        print(f"[JOB] Re-assigning ride to next nearest driver: {next_driver_obj.name} ({next_driver_obj.email})")
        new_ride = RideRequest(
            user_email=user_email,
            driver_email=next_driver_obj.email,
            user_latitude_at_request=user.latitude,
            user_longitude_at_request=user.longitude,
            status='Pending'
        )
        db.session.add(new_ride)
        db.session.commit() # Saves both the 'timed_out' old request and the new 'Pending' one.

        # 5. (ap--scheduler)Schedule a check for this NEW ride, crucially PASSING THE UPDATED EXCLUSION LIST.
        run_time = datetime.now(timezone.utc) + timedelta(seconds=30) # Or whatever your desired timeout is.
        
        scheduler.add_job(
            check_and_reroute_ride, 
            'date', 
            run_date=run_time, 
            # Pass the updated exclusion list to the next job in the chain.
            args=[new_ride.id, user_email, excluded_drivers]
        )
        print(f"[JOB] Scheduled next check for new ride {new_ride.id} at {run_time.isoformat()} with exclusions: {excluded_drivers}")

        # 6. Notify the user of the successful reroute and notify the NEW driver of their request.
        # Notify user of the new suggestion.
        socketio.emit('new_suggestion', {
            'message': f"Request to the previous driver timed out. Now requesting from next nearest driver: {next_driver_obj.name}.",
            'driver_name': next_driver_obj.name
        }, room=user_email)
        
        # Notify the new driver of their new request.
        new_driver_data = {
            'id': new_ride.id,
            'user_name': user.name,
            'user_email': user.email,
            'user_latitude': new_ride.user_latitude_at_request,
            'user_longitude': new_ride.user_longitude_at_request,
            'timestamp': format_datetime_npt(new_ride.timestamp),
            'status': new_ride.status
        }
        socketio.emit('new_ride_request', new_driver_data, room=next_driver_obj.email)

# ----------------------------Routes start from here------------------------------------------------
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
        elif not re.match(r"^9\d{9}$", phone):
            errors.append("Invalid phone number format. It must be exactly 10 digits and start with '9'.")
        
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

        
        # Securely hash the password provided by the user
        hashed_password = generate_password_hash(password)

        if role == 'driver':
    # Save the HASHED password, not the plain text one
            new_entity = Driver(email=email, name=name, phone=phone, password=hashed_password, vehicle=vehicle, node=node_from_form) 
        else: 
    # Save the HASHED password for the user as well
            new_entity = User(email=email, name=name, phone=phone, password=hashed_password, latitude=None, longitude=None)
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
            if driver and check_password_hash(driver.password, password):
                if not driver.is_approved:
                    flash('Your driver account is pending approval from an administrator.', 'warning')
                    return render_template('login.html', form_data=form_data_to_pass)
                session['driver'] = driver.email
                flash(f'Welcome,', 'success')
                login_successful = True
                return redirect(url_for('driver_home'))
            
        elif role == 'user':
             user = User.query.filter_by(email=email).first() #sqlinjection
             if user and check_password_hash(user.password, password): 
                session['user'] = user.email
                flash(f'Welcome', 'success')
                login_successful = True
                return redirect(url_for('user_home'))
        
        elif role == 'admin':
            admin = Admin.query.filter_by(email=email).first()
            if admin and check_password_hash(admin.password, password):
                session['admin'] = admin.email
                flash(f'Welcome, Administrator {admin.name}!', 'success')
                return redirect(url_for('admin_dashboard'))
            
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
     # 1. Receives the start node from the browser's request
    data = request.get_json()
    if not data: 
        return jsonify({'error': 'Invalid request: No JSON data received', 'success': False}), 400
    
    user_closest_node = data.get('user_closest_node') #give user closest node using hav

    selected_vehicle_type = data.get('vehicle_type', "").strip().lower() # Get selected vehicle type, lowercase for case-insensitive compare
    drivers_to_exclude = data.get('exclude_drivers', [])

    if not user_closest_node or user_closest_node not in graph or user_closest_node not in coordinates:
        return jsonify({'error': 'Invalid or missing user_closest_node for Dijkstra.', 'success': False}), 400
    
    driver_query = Driver.query.filter(
        Driver.node.isnot(None), 
        Driver.node.in_(graph.keys()),
        Driver.is_approved == True
    )
    if drivers_to_exclude:
        print(f"Executing search, excluding driver: {drivers_to_exclude}")
        driver_query = driver_query.filter(Driver.email.notin_(drivers_to_exclude))

    # Further filter by vehicle type if one is selected
    if selected_vehicle_type:
        driver_query = driver_query.filter(db.func.lower(Driver.vehicle).contains(selected_vehicle_type))
       
    # 2. Gets a list of all available and approved drivers from the database   
    available_drivers = driver_query.all()
    nearest_driver_info = None
    min_distance = float('inf')

    if not available_drivers: 
        message = f"No '{selected_vehicle_type if selected_vehicle_type else 'available'}' drivers found matching criteria."
        if not selected_vehicle_type: message = "No drivers currently available or their nodes are not in routing graph."
        return jsonify({'message': message, 'success': True, 'nearest_driver': None})

# 3. THIS IS THE CORE ALGORITHM LOOP
    for driver in available_drivers:
       
     # For each driver, it calls your Dijkstra implementation
        # It passes the graph, the user's start node, and the driver's current node
        # --- REDIRECTION TO dijkstra.py ---   
        distance = dijkstra(graph, user_closest_node, driver.node)
        # --- END REDIRECTION ---

        print(f"Dijkstra: UserNode '{user_closest_node}' to DriverNode '{driver.node}' (Driver: {driver.name}, Vehicle: {driver.vehicle}): dist {distance}")

     # 4. It compares the result to find the minimum distance
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
    # 5. The function finishes by returning the details of the best driver found.
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
        RideRequest.user_email == user_email,  #sqlinjection
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
        # ap--scheduler for check out 
        # Run the job 1 minutes from now
        run_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        scheduler.add_job(
            check_and_reroute_ride, 
            'date', 
            run_date=run_time, 
            args=[new_ride.id, user_email] # Pass the ride_id and user_email to the job
        )
        print(f"[SCHEDULER] Job scheduled for ride ID {new_ride.id} at {run_time.isoformat()}")
        #end of scheduling 

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
            'user_latitude_for_route': req.user_latitude_at_request, # Send user's location for consistency
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
            'driver_email': driver_rejecting.email, 
            'message': f"Your ride request was rejected by {driver_rejecting.name if driver_rejecting else 'a driver'}. Please find another."
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
    drivers_with_nodes = Driver.query.filter(
    Driver.node.isnot(None), 
    Driver.is_approved == True ).all()

    driver_list_for_js = [
    {'email': d.email, 'name': d.name, 'vehicle': d.vehicle, 'node': d.node}
    for d in drivers_with_nodes if d.node in coordinates]
    
    current_ride_status_info = None #Ride status
    accepted_ride_db = RideRequest.query.filter_by(user_email=user.email, status='accepted').order_by(RideRequest.timestamp.desc()).first()

    if accepted_ride_db:
        driver_obj = Driver.query.get(accepted_ride_db.driver_email)
        # Ensure all necessary location data is present for an accepted ride
        if driver_obj and driver_obj.node and driver_obj.node in coordinates and \
           accepted_ride_db.user_latitude_at_request is not None and \
           accepted_ride_db.user_longitude_at_request is not None:
            current_ride_status_info = {
                'ride_id': accepted_ride_db.id,
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
    # end of logic to determine current_ride_status_info 

    #gGet unique vehicle types from Driver table for the dropdown 
    vehicle_types_query = db.session.query(Driver.vehicle).filter(Driver.vehicle.isnot(None), Driver.vehicle != '').distinct().all()

    vehicle_types = sorted([vt[0] for vt in vehicle_types_query if vt[0]]) 
    print(f"[User Dashboard] Unique Vehicle Types Found: {vehicle_types}")
    # end of unique vehicle types 

    response = make_response(render_template('user_dashboard.html', 
                                                user=user, 
                                                drivers_for_js=driver_list_for_js, 
                                                coords=coordinates, # For driver node locations
                                                current_ride_status=current_ride_status_info, 
                                                graph_for_js=graph, # For Dijkstra path visualization
                                                vehicle_types=vehicle_types,
                                                services=emergency_services )) # Pass to template
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
    
    # ensure driver is passed here
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
        # get data from form
        new_name = request.form.get('name', '').strip()
        new_phone = request.form.get('phone', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # update name and phone if provided and different
        if new_name and new_name != user.name:
            user.name = new_name
            flash('Name updated successfully.', 'success')
        
        if new_phone and new_phone != user.phone:
            # add phone number validation if needed
            user.phone = new_phone
            flash('Phone number updated successfully.', 'success')

        # update password if new password is provided and matches confirmation
        if new_password:
           if new_password == confirm_password:
              user.password = generate_password_hash(new_password) # Hash the new password
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
              driver.password = generate_password_hash(new_password) # Hash the new password
              flash('Password updated.', 'success')
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error updating driver profile: {e}")
            flash('Error updating profile.', 'error')
        
        return redirect(url_for('edit_driver_profile'))

    response = make_response(render_template('edit_driver_profile.html', driver=driver, nodes=coordinates.keys(), title="Edit Driver Profile"))
    return add_no_cache_to_response(response)

@app.route('/admin/dashboard')
@login_required_admin
def admin_dashboard():
    admin = Admin.query.get(session['admin'])
    unapproved_drivers = Driver.query.filter_by(is_approved=False).all()
    
    # Some quick stats for the dashboard
    stats = {
        'total_users': User.query.count(),
        'total_drivers': Driver.query.filter_by(is_approved=True).count(),
        'pending_drivers': len(unapproved_drivers),
        'total_rides': RideRequest.query.count()
    }
    
    response = make_response(render_template(
        'admin_dashboard.html', 
        admin=admin, 
        unapproved_drivers=unapproved_drivers,
        stats=stats
    ))
    return add_no_cache_to_response(response)

@app.route('/admin/approve-driver/<driver_email>', methods=['POST'])
@login_required_admin
def approve_driver(driver_email):
    driver = Driver.query.get(driver_email)
    if not driver:
        return jsonify({'success': False, 'message': 'Driver not found.'}), 404
    
    driver.is_approved = True
    db.session.commit()
    
    flash(f"Driver '{driver.name}' has been approved.", "success")
    return jsonify({'success': True, 'message': f"Driver {driver.name} approved."})

@app.route('/admin/disapprove-driver/<driver_email>', methods=['POST'])
@login_required_admin
def disapprove_driver(driver_email):
    """
    Deletes a driver's pending registration record.
    """
    driver = Driver.query.filter_by(email=driver_email, is_approved=False).first()
    
    if not driver:
        return jsonify({'success': False, 'message': 'Pending driver not found or is already approved.'}), 404
    
    driver_name = driver.name
    
    db.session.delete(driver)
    db.session.commit()
    
    flash(f"Pending registration for '{driver_name}' has been disapproved and removed.", "success")
    return jsonify({'success': True, 'message': f"Pending registration for {driver_name} removed."})

@app.route('/admin/manage-users')
@login_required_admin
def manage_users():
    admin = Admin.query.get(session['admin'])
    all_users = User.query.all()
    response = make_response(render_template('admin_manage_users.html', admin=admin, users=all_users))
    return add_no_cache_to_response(response)

@app.route('/admin/manage-drivers')
@login_required_admin
def manage_drivers():
    admin = Admin.query.get(session['admin'])
    all_drivers = Driver.query.order_by(Driver.is_approved.asc()).all()
    response = make_response(render_template('admin_manage_drivers.html', admin=admin, drivers=all_drivers))
    return add_no_cache_to_response(response)
@app.route('/admin/delete-user/<user_email>', methods=['POST'])
@login_required_admin
def delete_user(user_email):
    # Find the user to be deleted from the User table.
    user = User.query.get(user_email)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    user_name = user.name # Store the name for the flash message.
    
    try:
        # Delete the user from the database.
        db.session.delete(user)
        
        # Anonymize their ride requests to preserve history.
        RideRequest.query.filter_by(user_email=user_email).update({"user_email": "deleted_user@evts.com"})
        
        db.session.commit()
        
        flash(f"User '{user_name}' and their associated ride records have been permanently deleted.", "success")
        return jsonify({'success': True, 'message': f"User {user_name} has been deleted."})

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user {user_email}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while trying to delete the user.'}), 500
    
@app.route('/admin/delete-driver/<driver_email>', methods=['POST'])
@login_required_admin
def delete_driver(driver_email):
    # Find the driver to be deleted.
    driver = Driver.query.get(driver_email)
    
    if not driver:
        # If the driver doesn't exist, return an error.
        return jsonify({'success': False, 'message': 'Driver not found.'}), 404
    
    driver_name = driver.name # Store the name for the flash message before deleting.
    
    try:
        # This is where the driver is deleted from the database.
        db.session.delete(driver)
        
        # We also need to handle any rides associated with this driver.
        # A simple approach is to anonymize them.
        # A more complex approach could be to delete them, but that loses history.
        RideRequest.query.filter_by(driver_email=driver_email).update({"driver_email": "deleted_driver@evts.com"})

        db.session.commit() # Commit the changes to the database.
        
        flash(f"Driver '{driver_name}' and their associated ride records have been permanently deleted.", "success")
        return jsonify({'success': True, 'message': f"Driver {driver_name} has been deleted."})

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting driver {driver_email}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while trying to delete the driver.'}), 500

@app.route('/admin/ride-history')
@login_required_admin
def global_ride_history():
    admin = Admin.query.get(session['admin'])
    all_rides = RideRequest.query.order_by(RideRequest.timestamp.desc()).all()
    
    enriched_rides = []
    for ride in all_rides:
        user = User.query.get(ride.user_email)
        driver = Driver.query.get(ride.driver_email)
        enriched_rides.append({
            'ride': ride,
            'user_name': user.name if user else 'N/A',
            'driver_name': driver.name if driver else 'N/A',
            'timestamp': format_datetime_npt(ride.timestamp) # Use your existing helper
        })

    response = make_response(render_template('admin_ride_history.html', admin=admin, rides=enriched_rides))
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
    
@socketio.on('send_chat_message')
def handle_chat_message(data):
    """Handle receiving a chat message and relaying it."""
    message_text = data.get('message')
    ride_id = data.get('ride_id')
    sender_role = data.get('role') # 'user' or 'driver'

    if not all([message_text, ride_id, sender_role]):
        # Ignore malformed messages
        return

    # Find the active ride to get the recipient's email
    active_ride = db.session.get(RideRequest, ride_id)
    if not active_ride or active_ride.status != 'accepted':
        # Don't relay messages for non-active rides
        return

    if sender_role == 'user':
        # User is sending, so the recipient is the driver
        recipient_email = active_ride.driver_email
    elif sender_role == 'driver':
        # Driver is sending, so the recipient is the user
        recipient_email = active_ride.user_email
    else:
        return # Invalid role

    # Prepare the payload to send to the recipient
    message_payload = {
        'message': message_text,
        'sender': sender_role
    }

    # Emit the message to the recipient's private room espically mail
    socketio.emit('receive_chat_message', message_payload, room=recipient_email)
    print(f"Relayed chat message for ride {ride_id} from {sender_role} to {recipient_email}: {message_text}")


if __name__ == '__main__':
    print("Starting Flask-SocketIO server with eventlet...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=True)