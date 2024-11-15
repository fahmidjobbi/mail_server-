import smtplib
import jwt
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import get_settings
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import html

################## Flask App Config ###################
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change to a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
########################################################

################## Configuration ###################
settings, config = get_settings()
email_server = settings.get('email_server')
password_email_server = settings.get('password_email_server')
smtp_server = settings.get('smtp_server')
smtp_port = settings.get('smtp_port')
########################################################################

# User Model for SQLAlchemy
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Create the database and the user table
#with app.app_context():
     #db.create_all()

# Token-based authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing!'}), 401
        
        # Extract the token from the header
        token = auth_header.split(" ")[1] if " " in auth_header else None
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['user']).first()
            if not current_user:
                return jsonify({'error': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def send_email(email, subject, mail_body):
    try:
        message = MIMEMultipart()
        message['From'] = email_server
        message['To'] = email
        message['Subject'] = subject
        message.attach(MIMEText(mail_body, 'html'))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_server, password_email_server)
            server.sendmail(email_server, email, message.as_string())
    except Exception as e:
        print('Error:', e)
        return (False, str(e))

    return (True, 'Email sent successfully')

################## Routes ###################

# Register route to add new users (for testing)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Please provide both username and password'}), 400

    # Use 'pbkdf2:sha256' for password hashing
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'User already exists or other error occurred'}), 500

# Login route to authenticate users and generate tokens
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Please provide both username and password'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# Main route to send emails, protected by token
@app.route('/send_email', methods=['POST'])
@token_required
def send_email_route(current_user):
    data = request.get_json()

    # Validate the incoming data
    if not data or 'email' not in data:
        return jsonify({'error': 'Invalid input, please provide an email address'}), 400

    emails = data.get('email')
    if isinstance(emails, str):
        emails = [emails]
    elif not isinstance(emails, list):
        return jsonify({'error': 'Email must be a string or a list of strings'}), 400

    subject = data.get('subject', 'No Subject')
    mail_body = data.get('body', 'No content provided.')

    # Escape user input to prevent XSS
    mail_body = html.escape(mail_body)

    # Create the HTML email body
    email_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .highlight {{
                    background-color: #f0f0f0;
                    padding: 8px;
                    font-weight: bold;
                    font-size: 16px;
                    color: #333;
                    font-family: Arial, sans-serif;
                }}
            </style>
        </head>
        <body>
            <p class="highlight">{mail_body}</p>
            <p>Regards,<br>{email_server}</p>
        </body>
        </html>
    """

    # Send the email to each recipient and handle exceptions
    responses = []
    for email in emails:
        try:
            success, message = send_email(email, subject, email_body)
            responses.append({'email': email, 'success': success, 'message': message})
        except Exception as e:
            responses.append({'email': email, 'success': False, 'message': str(e)})

    # Return a summary of email sending results
    return jsonify({'responses': responses})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
