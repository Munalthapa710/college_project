from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from graph_with_coords import graph, coordinates # Driver nodes still use this
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex() # For development. Use a fixed, strong key for production.

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models (Updated for Lat/Lng) ---
class RideRequest(db.Model):
    __tablename__ = 'ride_request'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), nullable=False)
    driver_email = db.Column(db.String(100), nullable=False)
    user_latitude_at_request = db.Column(db.Float, nullable=True)
    user_longitude_at_request = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')

class User(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100)) # HASH PASSWORDS in production
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

class Driver(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100)) # HASH PASSWORDS in production
    vehicle = db.Column(db.String(50))
    node = db.Column(db.String(10), nullable=False) # Drivers still operate from predefined nodes

# --- Routes ---
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form['role']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            return 'Passwords do not match.' # Use flash messages

        if role == 'driver':
            if Driver.query.get(email):
                return 'Driver with this email already exists.'
            vehicle = request.form['vehicle']
            node_from_form = request.form.get('node')
            if not node_from_form or node_from_form not in coordinates:
                 return 'Driver must select a valid location node from the list.'
            new_driver = Driver(email=email, name=name, phone=phone, password=password, vehicle=vehicle, node=node_from_form)
            db.session.add(new_driver)
        else: # User
            if User.query.get(email):
                return 'User with this email already exists.'
            # Latitude/Longitude for user will be set from map interactions, not during registration form
            new_user = User(email=email, name=name, phone=phone, password=password, latitude=None, longitude=None)
            db.session.add(new_user)
        try:
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration commit: {e}")
            return "Error during registration. Please try again.", 500
            
    return render_template('register.html', nodes=coordinates.keys()) # Nodes for driver registration

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form['role']
        email = request.form['username'] 
        password = request.form['password']
        if role == 'driver':
            driver = Driver.query.get(email)
            if driver and driver.password == password: 
                session['driver'] = driver.email
                return redirect('/dashboard')
        elif role == 'user':
            user = User.query.get(email)
            if user and user.password == password: 
                session['user'] = user.email
                return redirect('/user-dashboard')
        return 'Invalid credentials.' 
    return render_template('login.html')


@app.route('/set-user-current-location', methods=['POST'])
def set_user_current_location():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in', 'success': False}), 403
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request: No JSON data received', 'success': False}), 400
    
    lat_str = data.get('latitude')
    lng_str = data.get('longitude')

    if lat_str is None or lng_str is None:
        return jsonify({'error': 'Latitude or longitude missing', 'success': False}), 400
    
    try:
        lat = float(lat_str)
        lng = float(lng_str)
        if not (-90 <= lat <= 90 and -180 <= lng <= 180): # Basic range check
            raise ValueError("Coordinates out of valid range.")
    except (ValueError, TypeError) as ve: # Catch TypeError if lat_str/lng_str aren't convertible
        print(f"Invalid lat/lng format or value: {ve}. Received lat='{lat_str}', lng='{lng_str}'")
        return jsonify({'error': f'Invalid latitude or longitude format/value.', 'success': False}), 400

    user_obj = User.query.get(session['user'])
    if user_obj:
        user_obj.latitude = lat
        user_obj.longitude = lng
        try:
            db.session.commit()
            return jsonify({'message': f'User location updated to ({lat:.6f}, {lng:.6f})', 
                            'success': True, 'latitude': lat, 'longitude': lng}), 200
        except Exception as e:
            db.session.rollback()
            print(f"DB Error setting user location: {e}")
            return jsonify({'error': 'Database error updating location.', 'success': False}), 500
    return jsonify({'error': 'User not found', 'success': False}), 404

@app.route('/request-ride', methods=['POST'])
def request_ride():
    if 'user' not in session:
        return jsonify({'message': 'Not logged in', 'success': False}), 403
    data = request.get_json()
    if not data:
         return jsonify({'message': 'Invalid request: No JSON data received', 'success': False}), 400
    driver_email = data.get('driver_email')
    if not driver_email:
        return jsonify({'message': 'Driver email missing', 'success': False}), 400
        
    user_email = session['user']

    RideRequest.query.filter(
        RideRequest.user_email == user_email, 
        RideRequest.status.in_(['Pending', 'accepted'])
    ).update({'status': 'superseded'}, synchronize_session='fetch')
    db.session.commit() 

    requesting_user = User.query.get(user_email)
    if not requesting_user:
        return jsonify({'message': 'Requesting user not found.', 'success': False}), 404
    
    if requesting_user.latitude is None or requesting_user.longitude is None:
        return jsonify({'message': 'Your precise location is not set. Please click the map to set your location before requesting a ride.', 'success': False}), 400

    new_ride = RideRequest(
        user_email=user_email,
        driver_email=driver_email,
        user_latitude_at_request=requesting_user.latitude,
        user_longitude_at_request=requesting_user.longitude,
        timestamp=datetime.utcnow(),
        status='Pending'
    )
    db.session.add(new_ride)
    try:
        db.session.commit()
        return jsonify({'message': f'Ride requested successfully from driver {driver_email}!', 'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"DB Error creating ride request: {e}")
        return jsonify({'message': 'Error creating ride request. Please try again.', 'success': False}), 500

@app.route('/dashboard') # Driver Dashboard
def dashboard():
    if 'driver' not in session: return redirect('/login')
    driver = Driver.query.get(session['driver'])
    if not driver or not driver.node or driver.node not in coordinates:
        session.pop('driver', None)
        return "Driver profile error: Your location node is not set or invalid.", 400

    pending_requests_db = RideRequest.query.filter_by(driver_email=driver.email, status='Pending').order_by(RideRequest.timestamp.asc()).all()
    pending_serialized = []
    for r_db in pending_requests_db:
        user_obj = User.query.get(r_db.user_email)
        if r_db.user_latitude_at_request is not None and r_db.user_longitude_at_request is not None:
            pending_serialized.append({
                'id': r_db.id, 'user_email': r_db.user_email,
                'user_name': user_obj.name if user_obj else "Unknown User", 
                'user_latitude': r_db.user_latitude_at_request,
                'user_longitude': r_db.user_longitude_at_request,
                'timestamp': r_db.timestamp.strftime('%Y-%m-%d %H:%M'),
                'status': r_db.status
            })
        else:
            print(f"Warning (Driver Dashboard): Pending request ID {r_db.id} has missing user lat/lng.")
    
    active_ride_db = RideRequest.query.filter_by(driver_email=driver.email, status='accepted').first()
    active_ride_serialized = None
    if active_ride_db:
        user_obj = User.query.get(active_ride_db.user_email)
        if active_ride_db.user_latitude_at_request is not None and active_ride_db.user_longitude_at_request is not None:
            active_ride_serialized = {
                'id': active_ride_db.id, 'user_email': active_ride_db.user_email,
                'user_name': user_obj.name if user_obj else "Unknown",
                'user_latitude': active_ride_db.user_latitude_at_request,
                'user_longitude': active_ride_db.user_longitude_at_request,
                'timestamp': active_ride_db.timestamp.strftime('%Y-%m-%d %H:%M'),
            }
        else:
            print(f"Warning (Driver Dashboard): Active ride ID {active_ride_db.id} has missing user lat/lng.")

    return render_template('driver_dashboard.html', driver=driver, coords=coordinates,
                           pending_requests=pending_serialized, active_ride=active_ride_serialized)

@app.route('/user-dashboard')
def user_dashboard():
    if 'user' not in session: return redirect('/login')
    user = User.query.get(session['user']) # User object, contains user.latitude, user.longitude
    if not user:
        session.pop('user', None)
        return redirect('/login')

    drivers_for_js_finding = Driver.query.filter(Driver.node.isnot(None)).all()
    driver_list_for_js = [{'email': d.email, 'name': d.name, 'vehicle': d.vehicle, 'node': d.node}
                          for d in drivers_for_js_finding if d.node in coordinates]
    
    current_ride_status_info = None
    accepted_ride_db = RideRequest.query.filter_by(user_email=user.email, status='accepted').order_by(RideRequest.timestamp.desc()).first()

    if accepted_ride_db:
        driver_obj = Driver.query.get(accepted_ride_db.driver_email)
        if driver_obj and driver_obj.node and driver_obj.node in coordinates and \
           accepted_ride_db.user_latitude_at_request is not None and \
           accepted_ride_db.user_longitude_at_request is not None:
            current_ride_status_info = {
                'type': 'accepted', 'driver_name': driver_obj.name,
                'driver_node': driver_obj.node, 
                'user_latitude_for_route': accepted_ride_db.user_latitude_at_request,
                'user_longitude_for_route': accepted_ride_db.user_longitude_at_request,
                'timestamp': accepted_ride_db.timestamp.strftime('%Y-%m-%d %H:%M'),
                'message': f"Your ride with {driver_obj.name} is confirmed! Driver is en route."
            }
        else:
            print(f"Warning (User Dashboard): Accepted ride ID {accepted_ride_db.id} has invalid location data. Driver Node: {driver_obj.node if driver_obj else 'N/A'}, User Lat: {accepted_ride_db.user_latitude_at_request}, User Lng: {accepted_ride_db.user_longitude_at_request}")
            current_ride_status_info = {'type': 'error', 'message': 'Error displaying accepted ride details (location data issue).', 'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M')}
    else:
        pending_ride_db = RideRequest.query.filter_by(user_email=user.email, status='Pending').order_by(RideRequest.timestamp.desc()).first()
        if pending_ride_db:
            driver_obj = Driver.query.get(pending_ride_db.driver_email)
            driver_name_pending = driver_obj.name if driver_obj else pending_ride_db.driver_email
            current_ride_status_info = {'type': 'pending', 'driver_name': driver_name_pending,
                                        'timestamp': pending_ride_db.timestamp.strftime('%Y-%m-%d %H:%M'),
                                        'message': f"Your request to {driver_name_pending} is pending..."}
        else:
            last_inactive_ride_db = RideRequest.query.filter_by(user_email=user.email).filter(RideRequest.status.in_(['rejected', 'superseded'])).order_by(RideRequest.timestamp.desc()).first()
            if last_inactive_ride_db:
                driver_obj = Driver.query.get(last_inactive_ride_db.driver_email)
                driver_name_inactive = driver_obj.name if driver_obj else last_inactive_ride_db.driver_email
                msg = f"Your previous request to {driver_name_inactive} was {last_inactive_ride_db.status}."
                if last_inactive_ride_db.status == 'superseded': msg = f"Your previous active request was superseded."
                current_ride_status_info = {'type': last_inactive_ride_db.status, 'driver_name': driver_name_inactive,
                                            'timestamp': last_inactive_ride_db.timestamp.strftime('%Y-%m-%d %H:%M'), 'message': msg}

    return render_template('user_dashboard.html', user=user, drivers_for_js=driver_list_for_js, 
                           coords=coordinates, current_ride_status=current_ride_status_info)

@app.route('/accept-request', methods=['POST'])
def accept_request():
    if 'driver' not in session: return jsonify({'error': 'Not logged in', 'success': False}), 403
    data = request.get_json();
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
        return jsonify({'message': 'Request accepted', 'success': True}), 200
    except Exception as e:
        db.session.rollback(); print(f"DB Error accepting request: {e}")
        return jsonify({'error': 'Database error while accepting request.', 'success': False}), 500

@app.route('/reject-request', methods=['POST'])
def reject_request():
    if 'driver' not in session: return jsonify({'error': 'Not logged in', 'success': False}), 403
    data = request.get_json();
    if not data: return jsonify({'error': 'Invalid request', 'success': False}), 400
    req_id = data.get('id')
    if not req_id: return jsonify({'error': 'Request ID missing', 'success': False}), 400

    req = RideRequest.query.get(req_id)
    if not req: return jsonify({'error': 'Request not found', 'success': False}), 404
    if req.driver_email != session['driver']: return jsonify({'error': 'Unauthorized', 'success': False}), 403
    if req.status != 'Pending': return jsonify({'error': f'Request is not pending (status: {req.status})', 'success': False}), 400
    
    try:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'message': 'Request rejected', 'success': True}), 200
    except Exception as e:
        db.session.rollback(); print(f"DB Error rejecting request: {e}")
        return jsonify({'error': 'Database error while rejecting request.', 'success': False}), 500

@app.route('/complete-ride', methods=['POST'])
def complete_ride():
    if 'driver' not in session:
        return jsonify({'error': 'Not logged in as driver', 'success': False}), 403
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
        return jsonify({'message': 'Ride marked as completed successfully!', 'success': True}), 200
    except Exception as e:
        db.session.rollback(); print(f"DATABASE ERROR completing ride: {e}")
        return jsonify({'error': 'Database error while completing ride.', 'success': False}), 500

# --- Static Pages & History (remain largely same) ---
@app.route('/logout')
def logout(): session.clear(); return redirect('/login')
@app.route('/user-home')
def user_home(): 
    if 'user' not in session: return redirect('/login')
    user = User.query.get(session.get('user'))
    return render_template('user_home.html', user=user)
@app.route('/driver-home')
def driver_home(): 
    if 'driver' not in session: return redirect('/login')
    driver = Driver.query.get(session.get('driver'))
    return render_template('driver_home.html', driver=driver)
@app.route('/user-about')
def user_about(): 
    if 'user' not in session: return redirect('/login')
    return render_template('user_about.html')
@app.route('/driver-about')
def driver_about(): 
    if 'driver' not in session: return redirect('/login')
    return render_template('driver_about.html')

@app.route('/user-history') 
def user_history():
    if 'user' not in session: return redirect('/login')
    reqs_db = RideRequest.query.filter_by(user_email=session['user']).order_by(RideRequest.timestamp.desc()).all()
    s_reqs = []
    for r in reqs_db:
        d_obj = Driver.query.get(r.driver_email)
        s_reqs.append({'driver_name': d_obj.name if d_obj else r.driver_email, 
                       'status': r.status, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M')})
    return render_template('user_history.html', requests=s_reqs)

@app.route('/driver-history')
def driver_history():
    if 'driver' not in session: return redirect('/login')
    reqs_db = RideRequest.query.filter_by(driver_email=session['driver']).order_by(RideRequest.timestamp.desc()).all()
    s_reqs = []
    for r in reqs_db:
        u_obj = User.query.get(r.user_email)
        s_reqs.append({'user_name': u_obj.name if u_obj else r.user_email, 
                       'status': r.status, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M')})
    return render_template('driver_history.html', requests=s_reqs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)