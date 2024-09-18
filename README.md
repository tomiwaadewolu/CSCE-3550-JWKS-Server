# CSCE-3550-JWKS-Server

## Steps to making a RESTful JWKS Server
1. Set up the Development Environment (Flask for Python)
2. Generate RSA Pair Keys
3. JWKS Endpoint (GET /jwks)
4. Key Expiry and Rotation
5. JWT Signing and Issuance Endpoint (POST /token)
6. JWT Verification
7. Handle Expired JWTs
   
8. Secure the Authentication Endpoint

## Steps to Running the JWKS Server
1. Open a command line interface of your choice
2. Navigate to the folder with the server
3. Make sure Python is installed
4. To use a virtual environment (optional):
   
	a. Enter "python -m venv venv"

	b. Enter "venv\Scripts\activate"
5. Enter "pip install requests pyjwt cryptography" to install headers used
6. Start the server by running "python jwks_server.py"
7. Keep the server running while starting the test client

## Steps to Running the Test Client
Test Client: https://github.com/jh125486/CSCE3550/releases

1. Download the test client that works for your system
2. Open a different window of the command line interface
3. Navigate to the folder with the gradebot
   
4. Run "gradebot project1"

