# CSCE-3550-JWKS-Server

# Steps to making a RESTful JWKS Server
# 1. Set up the Development Environment (Flask for Python)
# 2. Generate RSA Pair Keys
# 3. JWKS Endpoint (GET /jwks)
# 4. Key Expiry and Rotation
# 5. JWT Signing and Issuance Endpoint (POST /token)
# 6. JWT Verification
# 7. Handle Expired JWTs
# 8. Secure the Authentication Endpoint

# Key Components Summary:
# -JWKS Endpoint (/jwks): Serves public keys in JSON Web Key format.
# -Token Issuance Endpoint (/token): Issues JWTs signed with private keys.
# -Key Expiry and Rotation: Regularly expire and replace old keys.
# -JWT Verification: Use kid in JWT header to verify against the corresponding public key in the JWKS.

# Optional Enhancements:
# -CORS: Enable CORS if necessary to allow clients from different origins to access the JWKS.
# -Rate Limiting: Apply rate limiting to the token issuance and JWKS endpoints for security.
# -Logging and Monitoring: Log access and key rotation events for monitoring.
