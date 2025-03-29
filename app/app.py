from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from datetime import datetime
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
from math import radians, sin, cos, sqrt, atan2
import requests


app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/django'  # Update with your MySQL URI
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # Replace with your own secret key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_JSON_KEY'] = 'identity'

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

    class ServiceLink(db.Model):
        __table__ = db.Table('myapp_salon_services', db.metadata, autoload_with=db.engine)    

    class Appointment(db.Model):
        __table__ = db.Table('myapp_appointment', db.metadata, autoload_with=db.engine)

    class BookedSlot(db.Model):
        __table__ = db.Table('myapp_bookedslot', db.metadata, autoload_with=db.engine)

    class ServiceFeedback(db.Model):
        __table__ = db.Table('myapp_servicefeedback', db.metadata, autoload_with=db.engine)

    class Category(db.Model):
        __table__ = db.Table('myapp_category', db.metadata, autoload_with=db.engine)

    db.create_all()


@app.route('/api/services/create', methods=['POST'])
@jwt_required()  # Requires authentication
def create_service():
    try:
        data = request.get_json()
        
        # Get authenticated owner's ID
        current_user_id = int(get_jwt_identity())

        print(f"Authenticated owner ID: {current_user_id}")  # Debugging line

        # Fetch the salon owner details
        owner = db.session.query(OwnerDetails).filter_by(id=current_user_id).first()
        if not owner:
            return jsonify({'error': 'Unauthorized access - Owner not found'}), 403

        print(f"Owner found: {owner.username}, ID: {owner.id}, Salon ID: {owner.salon_id}")  # Debugging line

        # Extract required fields for service
        name = data.get('name')
        price = data.get('price')
        duration = data.get('duration')
        category_id = data.get('category_id')
        image = data.get('image')
        salon_id = data.get('salon_id')

        # Validate required fields
        if not all([name, price, duration, salon_id]):
            return jsonify({
                'error': 'Missing required fields. Please provide name, price, duration, and salon_id.'
            }), 400

        # Ensure the salon exists and belongs to the authenticated owner
        salon = Salon.query.filter_by(id=salon_id).first()
        if not salon:
            return jsonify({'error': 'Salon not found'}), 404
        
        if owner.salon_id != salon.id:
            return jsonify({'error': 'Access denied. You can only create services for your own salon'}), 403

        print(f"Salon verified: {salon.salon_name}, Owner ID: {salon.id}")  # Debugging line

        # Check if category exists if category_id is provided
        if category_id:
            category = Category.query.get(category_id)
            if not category:
                return jsonify({'error': 'Category not found'}), 404

        # Create new service
        new_service = Service(
            name=name,
            price=price,
            duration=duration,
            category_id=category_id,
            image=image
        )

        db.session.add(new_service)
        db.session.commit()

        # Associate service with the salon
        new_salon_service = db.Table('myapp_salon_services', db.metadata, autoload_with=db.engine).insert().values(
            salon_id=salon_id,
            service_id=new_service.id
        )
        db.session.execute(new_salon_service)
        db.session.commit()

        return jsonify({
            'message': 'Service created successfully',
            'service': {
                'id': new_service.id,
                'name': new_service.name,
                'price': float(new_service.price),
                'duration': new_service.duration,
                'category_id': new_service.category_id,
                'image': new_service.image
            }
        }), 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        print(f"Error: {str(e)}")  # Debugging line
        return jsonify({'error': f'Failed to create service: {str(e)}'}), 500


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
@jwt_required()
def get_salon_details(id):
    try:
        # Get the authenticated user's ID from JWT token
        current_user_id = int(get_jwt_identity())  # Convert back to integer

        print(f"Authenticated owner ID: {current_user_id}")  # Debugging line

        # Fetch the salon owner details
        owner = db.session.query(OwnerDetails).filter_by(id=current_user_id).first()
        if not owner:
            return jsonify({'error': 'Unauthorized access - Owner not found'}), 403

        print(f"Owner found: {owner.username}, ID: {owner.id}, Salon ID: {owner.salon_id}")  # Debugging line

        # Ensure the requested salon belongs to the authenticated owner
        salon = Salon.query.filter_by(id=id).first()
        if not salon:
            return jsonify({'error': 'Salon not found'}), 404

        if owner.salon_id != salon.id:
            return jsonify({'error': 'Access denied. You can only access your own salon details'}), 403

        print(f"Salon found: {salon.salon_name}, Linked Owner ID: {salon.id}")  # Debugging line

        # Fetch related services for the salon
        services = db.session.query(Service).join(ServiceLink).filter(ServiceLink.salon_id == id).all()
        services_list = [{
            'id': service.id,
            'name': service.name,
            'image': service.image,
            'category': service.category_id
        } for service in services]

        # Fetch related categories based on the services
        category_ids = list(set([s.category_id for s in services if s.category_id]))  # Avoid duplicates
        categories = Category.query.filter(Category.id.in_(category_ids)).all()
        categories_list = [{
            'id': category.id,
            'name': category.name,
            'image': category.image
        } for category in categories]

        # Build the response
        response = {
            'salon': {
                'id': salon.id,
                'name': salon.salon_name,
                'address': salon.address
            },
            'owner': {
                'id': owner.id,
                'username': owner.username,
                'first_name': owner.first_name,
                'last_name': owner.last_name,
                'email': owner.email,
                'phone': owner.phone,
                'gender': owner.gender,
                'is_active': owner.is_active
            },
            'services': services_list,
            'categories': categories_list
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error: {str(e)}")  # Debugging line
        return jsonify({'error': f"An error occurred: {str(e)}"}), 500



@app.route('/api/salons', methods=['GET'])
def get_salons():
    salons = Salon.query.all()
    salons_list = [{
        'id': salon.id,
        'name': salon.salon_name,
        'image_name': salon.image
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
            date_joined=datetime.utcnow(),
            salon_id=new_salon.id
        )

        db.session.add(new_owner)
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
    
    token = create_access_token(identity=str(user.id))  # Convert to string

    
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


# ... existing code ...

# Calculate distance between two coordinates
def calculate_distance(lat1, lon1, lat2, lon2):
    # Earth radius in kilometers
    R = 6371.0
    
    lat1_rad = radians(lat1)
    lon1_rad = radians(lon1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    distance = R * c
    return distance

# Get nearby salons based on user location
GEOCODE_API_URL = "https://nominatim.openstreetmap.org/search"

def get_coordinates_from_address(address):
    """Fetch latitude and longitude for a given address using OpenStreetMap API."""
    try:
        params = {"q": address, "format": "json", "limit": 1}
        response = requests.get(GEOCODE_API_URL, params=params)
        data = response.json()
        if data:
            return float(data[0]['lat']), float(data[0]['lon'])
    except Exception as e:
        print("Error fetching coordinates:", e)
    return None, None

@app.route('/api/salons/nearby', methods=['GET', 'POST'])
def get_nearby_salons():
    try:
        if request.method == 'POST':
            data = request.get_json()
            user_lat = data.get('latitude')
            user_lon = data.get('longitude')
            radius = data.get('radius', 10)
            user_id = data.get('id')  # Updated to match `id` in `UserDetails`
        else:  # Handle GET request
            user_lat = request.args.get('lat', type=float)
            user_lon = request.args.get('lon', type=float)
            radius = request.args.get('radius', default=10, type=float)
            user_id = request.args.get('id', type=int)

        # If latitude & longitude are missing, fetch from the user's address
        if not user_lat or not user_lon:
            if not user_id:
                return jsonify({'error': 'User ID is required when lat/lon is missing'}), 400
            
            user = UserDetails.query.filter_by(id=user_id).first()
            if not user or not user.address_line:
                return jsonify({'error': 'Address not found for user'}), 400
            
            user_lat, user_lon = get_coordinates_from_address(user.address_line)
            if not user_lat or not user_lon:
                return jsonify({'error': 'Failed to get coordinates from address'}), 400

        salons = Salon.query.all()
        nearby_salons = []

        for salon in salons:
            if salon.latitude and salon.longitude:
                distance = calculate_distance(
                    float(user_lat), float(user_lon),
                    float(salon.latitude), float(salon.longitude)
                )
                if distance <= radius:
                    nearby_salons.append({
                        'id': salon.id,
                        'name': salon.salon_name,
                        'address': salon.address,
                        'latitude': salon.latitude,
                        'longitude': salon.longitude,
                        'distance': round(distance, 2),
                        'image': salon.image
                    })

        nearby_salons.sort(key=lambda x: x['distance'])
        return jsonify({'salons': nearby_salons}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get all cities/regions
@app.route('/api/regions', methods=['GET'])
def get_regions():
    try:
        # Fetch distinct cities from OwnerDetails table (linked via salon_id)
        regions = db.session.query(OwnerDetails.city).distinct().all()
        region_list = [region[0] for region in regions if region[0]]

        return jsonify({'regions': region_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get salons by region/city
@app.route('/api/salons/region/<region>', methods=['GET'])
def get_salons_by_region(region):
    try:
        # Fetch salons by joining Salon and OwnerDetails based on salon_id
        salons = db.session.query(Salon).join(OwnerDetails).filter(OwnerDetails.city == region).all()
        
        salon_list = [{
            'id': salon.id,
            'name': salon.salon_name,
            'address': salon.address,
            'image': salon.image
        } for salon in salons]
        
        return jsonify({'salons': salon_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get all categories
@app.route('/api/categories', methods=['GET'])
def get_categories():
    try:
        categories = Category.query.all()
        category_list = [{
            'id': category.id,
            'name': category.name,
            'image': category.image
        } for category in categories]
        
        return jsonify({'categories': category_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get services by category
@app.route('/api/services/category/<int:category_id>', methods=['GET'])
def get_services_by_category(category_id):
    try:
        services = Service.query.filter_by(category_id=category_id).all()
        service_list = [{
            'id': service.id,
            'name': service.name,
            'price': service.price,
            'duration': service.duration,
            'image': service.image
        } for service in services]
        
        return jsonify({'services': service_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Search endpoint for salons, categories, and services
@app.route('/api/search', methods=['GET'])
def search():
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({'salons': [], 'categories': [], 'services': []}), 200
            
        # Search salons
        salons = Salon.query.filter(Salon.salon_name.like(f'%{query}%')).all()
        salon_results = [{
            'id': salon.id,
            'name': salon.salon_name,
            'type': 'salon',
            'image': salon.image
        } for salon in salons]
        
        # Search categories
        categories = Category.query.filter(Category.name.like(f'%{query}%')).all()
        category_results = [{
            'id': category.id,
            'name': category.name,
            'type': 'category',
            'image': category.image
        } for category in categories]
        
        # Search services
        services = Service.query.filter(Service.name.like(f'%{query}%')).all()
        service_results = [{
            'id': service.id,
            'name': service.name,
            'type': 'service',
            'image': service.image
        } for service in services]
        
        # Combine results
        all_results = salon_results + category_results + service_results
        
        return jsonify({'results': all_results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)