from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from dijkstra import dijkstra, shortest_path
from graph_with_coords import graph, coordinates
import os


app = Flask(__name__)
app.secret_key = 'secret'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.route('/request-ride', methods=['POST'])
def request_ride():
    if 'user' not in session:
        return jsonify({'message': 'Not logged in'}), 403

    data = request.get_json()
    driver_email = data.get('driver_email')

    user = User.query.get(session['user'])  # ✅ properly scoped
    print(f"[DEBUG] Requesting user node: {user.node}")  # ✅ works now

    ride = RideRequest(
        user_email=session['user'],
        driver_email=driver_email,
        timestamp=datetime.utcnow(),
        status='Pending'
    )
    db.session.add(ride)
    db.session.commit()

    return jsonify({'message': 'Ride requested successfully!'})


class RideRequest(db.Model):
    __tablename__ = 'ride_request'  # explicitly define table name
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), nullable=False)
    driver_email = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')


class User(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100))
    node = db.Column(db.String(10))




class Driver(db.Model):
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    password = db.Column(db.String(100))
    vehicle = db.Column(db.String(50))
    node = db.Column(db.String(10))

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
            return 'Passwords do not match.'

        if role == 'driver':
            vehicle = request.form['vehicle']
            node = request.form['node']
            new_driver = Driver(email=email, name=name, phone=phone, password=password, vehicle=vehicle, node=node)
            db.session.add(new_driver)
        else:
            new_user = User(email=email, name=name, phone=phone, password=password, node='')
            db.session.add(new_user)

        db.session.commit()
        return redirect('/login')

    return render_template('register.html', nodes=coordinates.keys())

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

@app.route('/dashboard')
def dashboard():
    if 'driver' not in session:
        return redirect('/login')

    driver = Driver.query.get(session['driver'])

    users = User.query.all()
    for u in users:
        print(f"[DEBUG] User: {u.email}, Node: {u.node}")
    user_list = [{
        'email': u.email,
        'name': u.name,
        'phone': u.phone,
        'node': u.node
    } for u in users]

    pending_requests = RideRequest.query.filter_by(
        driver_email=session['driver'],
        status='Pending'
    ).order_by(RideRequest.timestamp.desc()).all()

    #  serialize pending requests
    pending_serialized = [{
        'id': r.id,
        'user_email': r.user_email,
        'driver_email': r.driver_email,
        'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M'),
        'status': r.status
    } for r in pending_requests]

    # this line must be inside the function!
    return render_template(
        'driver_dashboard.html',
        driver=driver,
        users=user_list,
        coords=coordinates,
        pending_requests=pending_serialized
    )

@app.route('/user-dashboard')
def user_dashboard():
    if 'user' not in session:
        return redirect('/login')

    user = User.query.get(session['user'])

    users = User.query.all()
    user_list = [{
        'email': u.email,
        'name': u.name,
        'phone': u.phone,
        'node': u.node
    } for u in users]

    drivers = Driver.query.all()
    driver_list = [{
        'email': d.email,
        'name': d.name,
        'vehicle': d.vehicle,
        'node': d.node
    } for d in drivers]

    # ✅ Add both pending and accepted requests
    ride_requests = RideRequest.query.filter_by(user_email=user.email).all()
    
    pending_serialized = []
    accepted_serialized = []

    for r in ride_requests:
        serialized = {
            'id': r.id,
            'user_email': r.user_email,
            'driver_email': r.driver_email,
            'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M'),
            'status': r.status
        }
        if r.status == 'Pending':
            pending_serialized.append(serialized)
        elif r.status == 'accepted':
            accepted_serialized.append(serialized)

    return render_template(
        'user_dashboard.html',
        user=user,
        users=user_list,
        drivers=driver_list,
        coords=coordinates,
        pending_requests=pending_serialized,     # ✅ Used in JS
        accepted_requests=[]   # ✅ Now added
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

with app.app_context():
    db.create_all()


@app.route('/user-home')
def user_home():
    if 'user' not in session:
        return redirect('/login')
    user = User.query.get(session['user'])
    return render_template('user_home.html', user=user)

@app.route('/driver-home')
def driver_home():
    if 'driver' not in session:
        return redirect('/login')
    driver = Driver.query.get(session['driver'])
    return render_template('driver_home.html', driver=driver)

@app.route('/user-about')
def user_about():
    if 'user' not in session:
        return redirect('/login')
    return render_template('user_about.html')

@app.route('/driver-about')
def driver_about():
    if 'driver' not in session:
        return redirect('/login')
    return render_template('driver_about.html')



@app.route('/user-history')
def user_history():
    if 'user' not in session:
        return redirect('/login')
    requests = RideRequest.query.filter_by(user_email=session['user']).order_by(RideRequest.timestamp.desc()).all()
    return render_template('user_history.html', requests=requests)


@app.route('/driver-history')
def driver_history():
    if 'driver' not in session:
        return redirect('/login')
    requests = RideRequest.query.filter_by(driver_email=session['driver']).order_by(RideRequest.timestamp.desc()).all()
    return render_template('driver_history.html', requests=requests)


@app.route('/accept-request', methods=['POST'])
def accept_request():
    data = request.json
    req = RideRequest.query.get(data['id'])
    if req and req.driver_email == session.get('driver'):
        req.status = 'accepted'
        db.session.commit()
    return '', 204

@app.route('/reject-request', methods=['POST'])
def reject_request():
    data = request.json
    req = RideRequest.query.get(data['id'])
    if req and req.driver_email == session.get('driver'):
        req.status = 'rejected'
        db.session.commit()
    return '', 204

from datetime import datetime

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # <-- This creates the RideRequest table
    app.run(debug=True)

