JWKS Server - Project 2 - README
=================================

CS 3550 Project 2 - SQLite Database Integration

REQUIREMENTS
------------
Python 3.8+

Package installation:
pip install -r requirements.txt

RUNNING
-------
python jwks_server.py

Server starts at http://127.0.0.1:8080
Creates database file: totally_not_my_privateKeys.db

TESTING
-------
JWKS endpoint: http://127.0.0.1:8080/.well-known/jwks.json
Auth endpoint: http://127.0.0.1:8080/auth

Test credentials:
Username: userABC
Password: password123

Test with gradebot:
gradebot.exe project2 -p 8080

FILES
-----
jwks_server.py - Main server file with SQLite integration
requirements.txt - Python dependencies
totally_not_my_privateKeys.db - SQLite database (created automatically)
readme.txt - This file
