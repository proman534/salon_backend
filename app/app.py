from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from datetime import datetime
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
from math import radians, sin, cos, sqrt, atan2


app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/django'  # Update with your MySQL URI
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # Replace with your own secret key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

geolocator = Nominatim(user_agent="salon_locator")

from app import db

db.init_app(app)

with app.app_context():
    class AuthGroup(db.Model):
        __table__ = db.Table('auth_group', db.metadata, autoload_with=db.engine)

    class AuthPermission(db.Model):
        __table__ = db.Table('auth_permission', db.metadata, autoload_with=db.engine)

    class UserDetails(db.Model):
        __table__ = db.Table('myapp_userdetails', db.metadata, autoload_with=db.engine)

    class OwnerDetails(db.Model):
        __table__ = db.Table('myapp_ownerdetails', db.metadata, autoload_with=db.engine)

    class Salon(db.Model):
        __table__ = db.Table('myapp_salon', db.metadata, autoload_with=db.engine)

    class Service(db.Model):
        __table__ = db.Table('myapp_service', db.metadata, autoload_with=db.engine)

    class Appointment(db.Model):
        __table__ = db.Table('myapp_appointment', db.metadata, autoload_with=db.engine)

    class BookedSlot(db.Model):
        __table__ = db.Table('myapp_bookedslot', db.metadata, autoload_with=db.engine)

    class ServiceFeedback(db.Model):
        __table__ = db.Table('myapp_servicefeedback', db.metadata, autoload_with=db.engine)

    db.create_all()

@app.route('/api/services', methods=['GET'])
def get_services():
    services = Service.query.all()
    services_list = [{
        'id': service.id,
        'name': service.name,
        'image_name': service.image
    } for service in services]
    return jsonify({'services': services_list})

@app.route('/users', methods=['GET'])
def get_users():
    users = UserDetails.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'email': user.email} for user in users])

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = UserDetails.query.get(user_id)
    if user:
        return jsonify({'id': user.id, 'name': user.name, 'email': user.email})
    return jsonify({'message': 'User not found'}), 404

@app.route('/users', methods=['POST'])
def add_user():
    data = request.json
    new_user = UserDetails(name=data['name'], email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User added successfully'}), 201

@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = UserDetails.query.get(user_id)
    if user:
        data = request.json
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    return jsonify({'message': 'User not found'}), 404

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = UserDetails.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'message': 'User not found'}), 404


@app.route('/api/salon_services/<int:id>', methods=['GET'])
def get_salon_details(id):
    try:
        # Fetch the salon along with its related services
        salon = Salon.query.filter_by(id=id).first()

        if not salon:
            return jsonify({'error': 'Salon not found'}), 404

        # If latitude and longitude are missing, fetch them
        

        # Fetch related services
        services = Service.query.filter_by(id=salon.id).all()
        services_list = [
            {
                'id': service.id,
                'name': service.name,
                'image': service.image,
            }
            for service in services
        ]

        # Construct response
        response = {
            'salon': {
                'id': salon.id,
                'name': salon.name,
                'address': salon.address,
                'latitude': salon.latitude,
                'longitude': salon.longitude,
            },
            'services': services_list
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error fetching salon details: {e}")
        return jsonify({'error': 'Unable to fetch salon details'}), 500

@app.route('/api/salons', methods=['GET'])
def get_salons():
    salons = Salon.query.all()
    salons_list = [{
        'id': salon.id,
        'name': salon.name,
        'image_name': salon.name
    } for salon in salons]
    return jsonify({'salons': salons_list})

# Register a new customer
@app.route('/register/customer', methods=['POST'])
def register_customer():
    data = request.get_json()
    
    username = data['username']
    password = data['password']
    email = data.get('email')
    phone = data.get('phone')
    
    # Check if username already exists
    if UserDetails.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = UserDetails(
        username=username, password=password_hash, 
        first_name=data.get('first_name'), last_name=data.get('last_name'),
        email=email, phone=phone, gender=data.get('gender'),
        date_of_birth=data.get('date_of_birth'),
        address_line=data['address_line'], city=data['city'], state=data['state'],
        pincode=data['pincode'], country=data['country'],
        is_superuser = request.json.get('is_superuser', False), is_staff  = request.json.get('is_staff', False), is_active = request.json.get('is_active', True), date_joined=datetime.utcnow()
  )
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Customer registered successfully"}), 201

def get_lat_lon_from_address(address):
    """Fetch latitude and longitude from an address using OpenStreetMap's Nominatim API."""
    try:
        location = geolocator.geocode(address, timeout=10)  # Timeout after 10 seconds
        if location:
            return location.latitude, location.longitude
    except GeocoderTimedOut:
        print(f"Geocoder timed out for address: {address}")
    except Exception as e:
        print(f"Error fetching lat/lon for {address}: {e}")
    return None, None  # Return None if geolocation fails

def calculate_distance(lat1, lon1, lat2, lon2):
    """ Haversine formula to calculate the distance between two latitude/longitude points. """
    R = 6371  # Radius of the Earth in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

@app.route('/register/salon_owner', methods=['POST'])
def register_salon_owner():
    data = request.get_json()

    required_fields = [
        'username', 'first_name', 'last_name', 'salon_name', 'email', 'phone',
        'gender', 'address', 'city', 'state', 'pin_code', 'country', 'password', 'confirm_password'
    ]
    
    # Check if all required fields are present
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

    username = data['username']
    email = data['email']
    password = data['password']
    confirm_password = data['confirm_password']

    # Password Confirmation Check
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    # Check if username or email already exists
    if OwnerDetails.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    if OwnerDetails.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Convert address to latitude and longitude
    full_address = f"{data['address']}, {data['city']}, {data['state']}, {data['pin_code']}, {data['country']}"
    latitude, longitude = get_lat_lon_from_address(full_address)

    if latitude is None or longitude is None:
        return jsonify({"error": "Invalid address. Could not fetch latitude and longitude."}), 400

    try:
        # Create new salon owner
        new_owner = OwnerDetails(
            username=username, password=password_hash,
            first_name=data['first_name'], last_name=data['last_name'],
            salon_name=data['salon_name'],
            email=email, phone=data['phone'], gender=data['gender'],
            address=data['address'], city=data['city'], state=data['state'],
            pin_code=data['pin_code'], country=data['country'],
            is_superuser=data.get('is_superuser', False),
            is_staff=data.get('is_staff', False),
            is_active=data.get('is_active', True),
            date_joined=datetime.utcnow()
        )

        db.session.add(new_owner)
        db.session.commit()

        # Create new salon entry linked to the owner
        new_salon = Salon(
            salon_name=data['salon_name'],
            address=data['address'],
            latitude=latitude,
            longitude=longitude,
            rating=0.0,  # Default rating
            image=None  # Can be updated later
        )

        db.session.add(new_salon)
        db.session.commit()

        return jsonify({"message": "Salon Owner registered successfully", "salon_id": new_salon.id}), 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

# Login an existing user
@app.route('/login/customer', methods=['POST'])
def customer_login():
    data = request.get_json()
    identifier = data.get('identifier')
    password = data.get('password')
    
    if not identifier or not password:
        return jsonify({"message": "Missing identifier or password"}), 400
    
    # Check UserDetails first
    user = UserDetails.query.filter(
        (UserDetails.username == identifier) | 
        (UserDetails.email == identifier) | 
        (UserDetails.phone == identifier)
    ).first()
    
    
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials"}), 400
    
    token = create_access_token(identity={'user_id': user.id, 'username': user.username})
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "username": user.username
    }), 200

# Middleware to verify JWT token
@app.route('/protected', methods=['GET'])
@jwt_required()
def customer_protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user['username']}!"}), 200


@app.route('/login/salon_owner', methods=['POST'])
def owner_login():
    data = request.get_json()
    identifier = data.get('identifier')
    password = data.get('password')
    
    if not identifier or not password:
        return jsonify({"message": "Missing identifier or password"}), 400
    
    # Check UserDetails first
    user = OwnerDetails.query.filter(
            (OwnerDetails.username == identifier) | 
            (OwnerDetails.email == identifier) | 
            (OwnerDetails.phone == identifier)
    ).first()
    
    
    
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials"}), 400
    
    token = create_access_token(identity={'user_id': user.id, 'username': user.username})
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "username": user.username
    }), 200

# Middleware to verify JWT token
@app.route('/protected', methods=['GET'])
@jwt_required()
def owner_protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user['username']}!"}), 200


# Get all salons
@app.route('/api/payments', methods=['POST'])
@jwt_required()  # Requires authentication
def process_payment():
    try:
        data = request.get_json()
        user_id = get_jwt_identity()["user_id"]
        amount = data.get("amount")
        method = data.get("method")  # e.g., "credit_card", "paypal", "upi"

        if not amount or not method:
            return jsonify({"error": "Amount and method are required"}), 400

        # Here, integrate your payment gateway logic (e.g., Stripe, Razorpay)
        # Simulating a successful payment response
        payment_response = {
            "status": "success",
            "transaction_id": "TXN12345678",
            "amount": amount,
            "method": method,
            "user_id": user_id
        }

        return jsonify(payment_response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Add these new routes to the existing Flask application

@app.route('/api/nearby_salons', methods=['GET'])
def get_nearby_salons():
    try:
        # Get user's current location from query parameters
        user_lat = float(request.args.get('lat'))
        user_lon = float(request.args.get('lon'))
        
        # Fetch all salons from the database
        salons = Salon.query.all()
        
        # Calculate distances and filter nearby salons
        nearby_salons = []
        for salon in salons:
            distance = calculate_distance(user_lat, user_lon, salon.latitude, salon.longitude)
            
            # Add salons within 20 km
            if distance <= 20:
                nearby_salons.append({
                    'id': salon.id,
                    'name': salon.name,
                    'address': salon.address,
                    'distance': round(distance, 2),
                    'latitude': salon.latitude,
                    'longitude': salon.longitude
                })
        
        # Sort salons by distance
        nearby_salons.sort(key=lambda x: x['distance'])
        
        return jsonify({'salons': nearby_salons})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search_suggestions', methods=['GET'])
def get_search_suggestions():
    try:
        query = request.args.get('query', '').lower()
        
        # Combine search across multiple tables
        salon_suggestions = Salon.query.filter(
            Salon.name.ilike(f'%{query}%')
        ).limit(5).all()
        
        service_suggestions = Service.query.filter(
            Service.name.ilike(f'%{query}%')
        ).limit(5).all()
        
        # Combine and deduplicate suggestions
        suggestions = set()
        
        for salon in salon_suggestions:
            suggestions.add(salon.name)
        
        for service in service_suggestions:
            suggestions.add(service.name)
        
        return jsonify({
            'suggestions': list(suggestions)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Optional: Add a route to get services by category
@app.route('/api/services/category', methods=['GET'])
def get_services_by_category():
    try:
        category = request.args.get('category')
        services = Service.query.filter_by(category=category).all()
        
        services_list = [{
            'id': service.id,
            'name': service.name,
            'category': service.category,
            'image': service.image
        } for service in services]
        
        return jsonify({'services': services_list})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)