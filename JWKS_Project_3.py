import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import sqlite3
from uuid import uuid4
import argon2
import time

hostName = "127.0.0.1"
serverPort = 8080

# Function to generate a secure password using UUIDv4
def generate_password():
    return str(uuid4())

# Function to hash password using Argon2
def hash_password(password):
    hasher = argon2.PasswordHasher()
    hashed_password = hasher.hash(password)
    return hashed_password

# Create or connect to the database
def connect_to_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            request_ip TEXT NOT NULL,
                            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            user_id INTEGER,  
                            FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    return conn, c


# Add user function
def add_user_to_db(conn, c, username, password_hash, email):
    c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
    conn.commit()

# Log authentication request
def log_auth_request(conn, c, ip, user_id):
    c.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
    conn.commit()

class MyServer(BaseHTTPRequestHandler):
    # HTTP requests
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Rate limiter for POST requests
    def rate_limit(self):
        ip = self.client_address[0]
        now = time.time()
        if ip in self.request_history:
            request_times = self.request_history[ip]
            request_times = [t for t in request_times if now - t <= 1]  # Filter requests within 1 second
            if len(request_times) >= 10:
                return False
            request_times.append(now)
            self.request_history[ip] = request_times
        else:
            self.request_history[ip] = [now]
        return True

    # POST:/register endpoint for user registration
    def do_POST(self):
        if self.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data)

            # Generate secure password
            password = generate_password()

            # Hash password using Argon2
            hashed_password = hash_password(password)

            # Connect to the database
            conn, c = connect_to_db()

            # Add user to the database
            add_user_to_db(conn, c, user_data['username'], hashed_password, user_data['email'])

            # Return password to the user
            response_data = {"password": password}
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())

            # Close the database connection
            conn.close()

            return

        elif self.path == "/auth":
            if not self.rate_limit():
                # Return 429 Too Many Requests
                self.send_response(429)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Too many requests"}).encode())
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            auth_data = json.loads(post_data)

            # Check authentication (dummy check for demonstration)
            # In a real scenario, you would validate credentials against the database
            if auth_data['username'] == "dummy_user" and auth_data['password'] == "dummy_password":
                user_id = 1  # Assuming user ID for the dummy user is 1

                # Connect to the database
                conn, c = connect_to_db()

                # Log authentication request
                log_auth_request(conn, c, self.client_address[0], user_id)

                # Close the database connection
                conn.close()

                # Return success response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Authentication successful"}).encode())
            else:
                # Return failure response
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Authentication failed"}).encode())

            return

        self.send_response(405)
        self.end_headers()
        return

    # Initialize request history dictionary
    def __init__(self, *args, **kwargs):
        self.request_history = {}
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
