# mail_server-
Flask Email Service with Token Authentication This is a Flask-based web service that allows users to register, log in, and send HTML-formatted emails with token-based authentication. 
The service uses JWT (JSON Web Token) for user authentication, and the emails are sent via SMTP with TLS encryption. This project also uses SQLAlchemy to manage users and stores their credentials in an SQLite database.

Key Features:
User Registration & Login:

Users can register by providing a username and password.
The password is hashed using pbkdf2:sha256 for secure storage.
JWT tokens are issued upon successful login, allowing users to make authorized requests.
Email Sending:

Authenticated users can send HTML-formatted emails to one or more recipients.
The email content is sanitized to prevent XSS (Cross-site Scripting) attacks.
The email service supports both single and multiple recipient email sending.
Supports SMTP with TLS encryption for secure email delivery.
Token-based Authentication:

Protected routes require a valid JWT token for access.
The token is checked for expiration and validity on every request.
SQLite Database:

User credentials are stored in an SQLite database using SQLAlchemy ORM.
The database table contains username and password fields.
Technologies Used:
Flask: Web framework for building the API.
SQLAlchemy: ORM for interacting with the SQLite database.
JWT (JSON Web Token): Token-based authentication for securing routes.
SMTP: Simple Mail Transfer Protocol used for sending emails.
Werkzeug: For securely hashing and verifying passwords.
Flask-CORS: To handle Cross-Origin Resource Sharing.
HTML Escaping: To prevent Cross-site Scripting (XSS) vulnerabilities in email content.
