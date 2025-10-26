"""
JWKS Server - Project 2 Implementation

Extended JWKS server with SQLite database for storing private keys.
Now keys are saved to disk and persist across server restarts.

Made by: [Recep Alperen Dalkir]
Date: 2025
"""

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify, Response


class JWKSKeyStore:
    """
    Manages RSA key pairs with SQLite database storage.
    Keys are now saved to disk so they survive server restarts.
    """
    
    def __init__(self, db_file: str = "totally_not_my_privateKeys.db"):
        """Initialize database and create tables if needed"""
        self.db_file = db_file
        self._init_database()
        self._generate_initial_keys()
    
    def _init_database(self) -> None:
        """
        Create the database and keys table if they don't exist.
        Table stores: kid (auto-increment ID), key (the private key as text), exp (expiry timestamp)
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create the keys table - using BLOB for key storage
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _generate_initial_keys(self) -> None:
        """
        Generate initial keys if the database is empty.
        Creates one valid key and one expired key for testing.
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Check if we already have keys
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Generate a valid key (expires in 1 hour)
            self._add_key_pair(expires_in_hours=1)
            
            # Generate an expired key (expired 1 hour ago)
            self._add_key_pair(expires_in_hours=-1)
        
        conn.close()
    
    def _add_key_pair(self, expires_in_hours: int = 24) -> int:
        """
        Generate a new RSA key pair and save it to the database.
        
        expires_in_hours: How many hours from now should this key expire?
        Returns the kid (database ID) of the new key
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Convert private key to PEM format (text string)
        # This is how we store it in the database
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Calculate expiry timestamp
        expiry = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
        exp_timestamp = int(expiry.timestamp())
        
        # Save to database using parameterized query (prevents SQL injection)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (private_pem, exp_timestamp)
        )
        
        kid = cursor.lastrowid  # Get the auto-generated kid
        conn.commit()
        conn.close()
        
        return kid
    
    def get_valid_key(self) -> Optional[Dict]:
        """
        Get a non-expired private key from the database.
        Returns the key info including kid and the actual key object.
        """
        now = int(datetime.now(timezone.utc).timestamp())
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get a key that hasn't expired yet
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
            (now,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        kid, key_pem, exp = row
        
        # Convert the PEM string back to a key object
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        
        return {
            'kid': kid,
            'private_key': private_key,
            'expiry': exp
        }
    
    def get_expired_key(self) -> Optional[Dict]:
        """
        Get an expired private key from the database.
        Used for testing the expired=true parameter.
        """
        now = int(datetime.now(timezone.utc).timestamp())
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get a key that has already expired
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
            (now,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        kid, key_pem, exp = row
        
        # Convert the PEM string back to a key object
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        
        return {
            'kid': kid,
            'private_key': private_key,
            'expiry': exp
        }
    
    def get_valid_keys_jwks(self) -> Dict:
        """
        Get all non-expired public keys from the database and format as JWKS.
        This is what gets returned from the /.well-known/jwks.json endpoint.
        """
        now = int(datetime.now(timezone.utc).timestamp())
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get all keys that haven't expired yet
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        )
        
        rows = cursor.fetchall()
        conn.close()
        
        jwks_keys = []
        for kid, key_pem in rows:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Get the public key from the private key
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Convert to base64url format
            n = self._int_to_base64url(public_numbers.n)
            e = self._int_to_base64url(public_numbers.e)
            
            # Build JWK object
            jwk = {
                'kty': 'RSA',
                'kid': str(kid),  # Convert kid to string for JSON
                'use': 'sig',
                'alg': 'RS256',
                'n': n,
                'e': e
            }
            jwks_keys.append(jwk)
        
        return {'keys': jwks_keys}
    
    def _int_to_base64url(self, value: int) -> str:
        """Convert integer to base64url format for JWKS"""
        import base64
        
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder='big')
        
        return base64.urlsafe_b64encode(value_bytes).decode('ascii').rstrip('=')


class JWKSServer:
    """
    Flask web server for JWKS endpoints.
    Now uses database-backed key storage.
    """
    
    def __init__(self, db_file: str = "totally_not_my_privateKeys.db"):
        """Set up Flask and database key store"""
        self.app = Flask(__name__)
        self.key_store = JWKSKeyStore(db_file)
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Configure Flask routes"""
        self.app.route('/.well-known/jwks.json', methods=['GET'])(self._jwks_endpoint)
        self.app.route('/auth', methods=['POST'])(self._auth_endpoint)
        self.app.errorhandler(405)(self._method_not_allowed)
    
    def _jwks_endpoint(self) -> Response:
        """
        Handle GET requests to /.well-known/jwks.json
        Returns all valid (non-expired) public keys from the database
        """
        if request.method != 'GET':
            return self._method_not_allowed_response()
        
        jwks = self.key_store.get_valid_keys_jwks()
        return jsonify(jwks)
    
    def _auth_endpoint(self) -> Response:
        """
        Handle POST requests to /auth
        Reads key from database and issues a JWT
        """
        if request.method != 'POST':
            return self._method_not_allowed_response()
        
        # Get credentials
        credentials = self._extract_credentials()
        if not credentials:
            return jsonify({'error': 'No credentials provided'}), 400
        
        username, password = credentials
        
        # Check credentials (hardcoded for this project)
        if username != 'userABC' or password != 'password123':
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if expired token is requested
        expired_requested = 'expired' in request.args
        
        if expired_requested:
            return self._issue_expired_jwt()
        else:
            return self._issue_valid_jwt()
    
    def _extract_credentials(self) -> Optional[Tuple[str, str]]:
        """Extract username and password from request"""
        # Try JSON body
        if request.is_json:
            data = request.get_json()
            if data and 'username' in data and 'password' in data:
                return data['username'], data['password']
        
        # Try form data
        if request.form:
            username = request.form.get('username')
            password = request.form.get('password')
            if username and password:
                return username, password
        
        # Try basic auth
        auth = request.authorization
        if auth:
            return auth.username, auth.password
        
        return None
    
    def _issue_valid_jwt(self) -> Response:
        """Issue a JWT signed with a valid (non-expired) key from database"""
        key_info = self.key_store.get_valid_key()
        if not key_info:
            return jsonify({'error': 'No valid keys available'}), 500
        
        # Create JWT payload
        now = datetime.now(timezone.utc)
        payload = {
            'iss': 'jwks-server',
            'sub': 'userABC',
            'aud': 'jwks-client',
            'exp': int((now + timedelta(hours=1)).timestamp()),
            'iat': int(now.timestamp()),
            'jti': str(uuid.uuid4())
        }
        
        # Sign with private key from database
        token = jwt.encode(
            payload,
            key_info['private_key'],
            algorithm='RS256',
            headers={'kid': str(key_info['kid'])}
        )
        
        return jsonify({'token': token})
    
    def _issue_expired_jwt(self) -> Response:
        """Issue a JWT signed with an expired key from database"""
        key_info = self.key_store.get_expired_key()
        if not key_info:
            return jsonify({'error': 'No expired keys available'}), 500
        
        # Create expired JWT payload
        now = datetime.now(timezone.utc)
        past_time = now - timedelta(hours=2)
        
        payload = {
            'iss': 'jwks-server',
            'sub': 'userABC',
            'aud': 'jwks-client',
            'exp': int((past_time + timedelta(minutes=30)).timestamp()),
            'iat': int(past_time.timestamp()),
            'jti': str(uuid.uuid4())
        }
        
        # Sign with expired private key from database
        token = jwt.encode(
            payload,
            key_info['private_key'],
            algorithm='RS256',
            headers={'kid': str(key_info['kid'])}
        )
        
        return jsonify({'token': token})
    
    def _method_not_allowed(self, error) -> Response:
        """Handle wrong HTTP methods"""
        return self._method_not_allowed_response()
    
    def _method_not_allowed_response(self) -> Response:
        """Return 405 error"""
        return jsonify({'error': 'Method not allowed'}), 405
    
    def run(self, host: str = '127.0.0.1', port: int = 8080, debug: bool = False) -> None:
        """Start the server"""
        print(f"Starting JWKS Server on {host}:{port}")
        print(f"Database: {self.key_store.db_file}")
        print(f"JWKS endpoint: http://{host}:{port}/.well-known/jwks.json")
        print(f"Auth endpoint: http://{host}:{port}/auth")
        print(f"Test credentials: userABC / password123")
        print("Press Ctrl+C to stop")
        
        self.app.run(host=host, port=port, debug=debug)


def main():
    """Start the server"""
    server = JWKSServer()
    try:
        server.run(debug=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == '__main__':
    main()