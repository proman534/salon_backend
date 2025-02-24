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

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    date_of_birth = db.Column(db.String(10), nullable=True)

# Customer model
class Customer(db.Model):
    __tablename__ = 'customers'
    customer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    date_of_birth = db.Column(db.String(10), nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    user = db.relationship('User', backref=db.backref('customers', lazy=True))

# SalonOwner model
class SalonOwner(db.Model):
    __tablename__ = 'salon_owners'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    salon_name = db.Column(db.String(100), nullable=True)
    address_id = db.Column(db.Integer, db.ForeignKey('addresses.id'), nullable=True)  # Reference Address table
    user = db.relationship('User', backref=db.backref('salon_owners', lazy=True))
    address = db.relationship('Address', backref=db.backref('salon_owner_relation', uselist=False), 
                              foreign_keys=[address_id])  # Rename the backref to `salon_owner_relation`
    password_hash = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.String(10), nullable=True)

# Address model
class Address(db.Model):
    __tablename__ = 'addresses'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    salon_owners_id = db.Column(db.Integer, db.ForeignKey('salon_owners.id'), nullable=True)  # ForeignKey to salon_owners table
    address_line = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('addresses', lazy=True), foreign_keys=[user_id])
    salon_owner = db.relationship('SalonOwner', backref=db.backref('addresses', lazy=True), foreign_keys=[salon_owners_id])
    
    def __init__(self, address_line, city, state, pin_code, country, user_id=None, salon_owners_id=None):
        self.address_line = address_line
        self.city = city
        self.state = state
        self.pin_code = pin_code
        self.country = country
        self.user_id = user_id
        self.salon_owners_id = salon_owners_id

    def __repr__(self):
        return f"<Address {self.address_line}, {self.city}, {self.state}, {self.country}>"

# Salons model (new table)
class Salon(db.Model):
    __tablename__ = 'salons'
    salon_id = db.Column(db.Integer, primary_key=True)
    salon_name = db.Column(db.String(100), nullable=False)
    salon_owner_id = db.Column(db.Integer, db.ForeignKey('salon_owners.id'), nullable=False)
    address_id = db.Column(db.Integer, db.ForeignKey('addresses.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=True, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)
    image_name = db.Column(db.String(100), nullable=False)

    # Relationships
    salon_owner = db.relationship('SalonOwner', backref=db.backref('salons', lazy=True))
    address = db.relationship('Address', backref=db.backref('salon', uselist=False))

    def __init__(self, salon_name, salon_owner_id, address_id):
        self.salon_name = salon_name
        self.salon_owner_id = salon_owner_id
        self.address_id = address_id

class Service(db.Model):
    __tablename__ = 'services'
    service_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    salon_id = db.Column(db.Integer, nullable=False)
    image_name = db.Column(db.String(100), nullable=False)

@app.route('/api/services', methods=['GET'])
def get_services():
    services = Service.query.all()
    services_list = [{
        'id': service.service_id,
        'name': service.name,
        'image_name': service.image_name
    } for service in services]
    return jsonify({'services': services_list})

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
