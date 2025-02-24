from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/django'  # Update with your MySQL URI
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # Replace with your own secret key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

from app import db

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

@app.route('/api/services', methods=['GET'])
def get_services():
    services = Service.query.all()
    services_list = [{
        'id': service.service_id,
        'name': service.name,
        'image_name': service.image_name
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


@app.route('/api/service/<int:salon_id>', methods=['GET'])
def get_service(salon_id):
    try:
        # Query the database for services matching the given salon_id
        services = Service.query.filter_by(salon_id=salon_id).all()
        
        # Convert the services to a list of dictionaries for JSON response
        services_list = [
            {
                'id': service.service_id,
                'name': service.name,
                'image_name': service.image_name,
            }
            for service in services
        ]
        
        return jsonify({'services': services_list}), 200

    except Exception as e:
        print(f"Error fetching services: {e}")
        return jsonify({'error': 'Unable to fetch services'}), 500

@app.route('/api/salons', methods=['GET'])
def get_salons():
    salons = Salon.query.all()
    salons_list = [{
        'id': salon.salon_id,
        'name': salon.salon_name,
        'image_name': salon.image_name
    } for salon in salons]
    return jsonify({'salons': salons_list})

# Register a new customer
@app.route('/register/customer', methods=['POST'])
def register_customer():
    data = request.get_json()
    
    # User details
    username = data['username']
    password = data['password']
    first_name = data.get('first_name', None)
    last_name = data.get('last_name', None)
    email = data.get('email', None)
    phone_number = data.get('phone_number', None)
    gender = data.get('gender', None)
    date_of_birth = data.get('date_of_birth', None)
    
    # Address details
    address_line = data['address_line']
    city = data['city']
    state = data['state']
    pin_code = data['pin_code']
    country = data['country']
    
    # Check if username exists
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"message": "Username already exists"}), 400

    # Hash password
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create user with role 'customer'
    new_user = User(username=username, password_hash=password_hash, first_name=first_name, last_name=last_name,
                    email=email, phone_number=phone_number, role='customer', gender=gender, date_of_birth=date_of_birth)
    db.session.add(new_user)
    db.session.commit()

    # Create address entry
    new_address = Address(address_line=address_line, city=city, state=state, pin_code=pin_code,
                          country=country, user_id=new_user.id)
    db.session.add(new_address)
    db.session.commit()

    # Create customer entry
    new_customer = Customer(user_id=new_user.id, gender=gender, date_of_birth=date_of_birth,password_hash=password_hash, first_name=first_name, last_name=last_name,
                    email=email, phone_number=phone_number)
    db.session.add(new_customer)
    db.session.commit()

    return jsonify({"message": "Customer registered successfully"}), 201


# Register a new salon owner
@app.route('/register/salon_owner', methods=['POST'])
def register_salon_owner():
    data = request.get_json()
    
    # User details
    username = data['username']
    password = data['password']
    first_name = data.get('first_name', None)
    last_name = data.get('last_name', None)
    email = data.get('email', None)
    phone_number = data.get('phone_number', None)
    gender = data.get('gender', None)
    
    # Salon details
    salon_name = data.get('salon_name', None)
    
    # Address details
    address_line = data['address_line']
    city = data['city']
    state = data['state']
    pin_code = data['pin_code']
    country = data['country']
    
    # Check if username exists
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"message": "Username already exists"}), 400

    # Hash password
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create user with role 'salon_owner'
    new_user = User(username=username, password_hash=password_hash, first_name=first_name, last_name=last_name,
                    email=email, phone_number=phone_number, role='salon_owner', gender=gender)
    db.session.add(new_user)
    db.session.commit()

    # Create address entry
    new_address = Address(address_line=address_line, city=city, state=state, pin_code=pin_code,
                          country=country, salon_owners_id=new_user.id)
    db.session.add(new_address)
    db.session.commit()

    # Create salon owner entry
    new_salon_owner = SalonOwner(user_id=new_user.id, salon_name=salon_name, password_hash=password_hash, first_name=first_name, last_name=last_name,
                    email=email, phone_number=phone_number, gender=gender)
    db.session.add(new_salon_owner)
    db.session.commit()

    # Create salon entry
    new_salon = Salon(salon_name=salon_name, salon_owner_id=new_salon_owner.id, address_id=new_address.id)
    db.session.add(new_salon)
    db.session.commit()

    return jsonify({"message": "Salon Owner registered successfully"}), 201


# Login an existing user
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('identifier')  # Single field for username, email, or phone
    password = data.get('password')

    if not identifier or not password:
        return jsonify({"message": "Missing identifier or password"}), 400

    # Query the database to find the user by username, email, or phone
    user = User.query.filter(
        (User.username == identifier) | 
        (User.email == identifier) | 
        (User.phone_number == identifier)
    ).first()

    # Validate user and password
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 400

    # Create a JWT token
    token = create_access_token(identity={'user_id': user.id, 'username': user.username, 'role': user.role})

    return jsonify({
        "message": "Login successful",
        "token": token,
        "role": user.role
    }), 200


# Middleware to verify JWT token
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user['username']}!"}), 200

# Fetch all users - Protected route
@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    users = User.query.all()
    users_list = [{'user_id': user.id, 'username': user.username, 'role': user.role} for user in users]
    return jsonify(users_list), 200

# Fetch a single user by ID - Protected route
@app.route('/users/<int:id>', methods=['GET'])
@jwt_required()
def get_user_by_id(id):
    user = User.query.get(id)
    if user:
        return jsonify({'user_id': user.id, 'username': user.username, 'role': user.role}), 200
    return jsonify({'message': 'User not found'}), 404


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


if __name__ == '__main__':
    app.run(debug=True)
