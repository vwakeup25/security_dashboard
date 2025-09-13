Vivek Security Dashboard
A full-stack security monitoring application featuring a real-time dashboard built with React and a powerful, secure backend powered by Python and FastAPI. This project is designed to capture, analyze, and securely store network data, using machine learning for anomaly detection and blockchain-inspired principles for log integrity.

## Key Features
Real-time Packet Capture: Ingests network packets in either a simulated mode for development or a real mode using Scapy (requires appropriate permissions and drivers).

Online ML Anomaly Detection: Utilizes the river library to perform streaming (online) machine learning, scoring each packet for anomalies in real-time without prior training.

Secure, Tamper-Evident Logging: Each log entry (Block) is cryptographically hashed and chained to the previous block. Hashes are digitally signed using Ed25519 keys to ensure integrity and non-repudiation.

Encrypted Log Storage: Sensitive portions of the log data are encrypted using Fernet (symmetric encryption) before being stored in the database.

JWT-based Authentication: The API is secured using JSON Web Tokens (JWT), with a login route that uses secure, hashed passwords.

Data Enrichment: Enriches incoming data with GeoIP information (Country/City) and reverse DNS lookups (Hostname).

PDF Log Export: Provides a feature to export the security logs into a formatted PDF report.

Modern Async Backend: Built with FastAPI for high performance and a modern developer experience.

## Technology Stack
### Backend
Framework: FastAPI

Database: SQLModel (on top of SQLAlchemy) with SQLite

Authentication: Passlib (for bcrypt), python-jose (for JWT)

Packet Capture: Scapy

Online Machine Learning: River

Configuration: Pydantic Settings

Dependency Management: pip-tools

### Frontend
Framework: React

UI Animations: Framer Motion

Toolchain: Create React App

## Setup and Installation
Follow these steps to get the backend running locally.

1. Clone the Repository

Bash

git clone https://github.com/vwakeup25/security_dashboard.git
cd security_dashboard/backend
2. Create and Activate Virtual Environment

PowerShell

# Create the environment
python -m venv venv

# Activate it (on Windows PowerShell)
.\venv\Scripts\Activate
3. Prepare Prerequisite Files
This application requires several files to be created before it can run.

.env File: Create a .env file in the backend directory with your configuration.

Code snippet

JWT_SECRET="a_very_strong_and_secret_key_that_you_create"
ADMIN_USER="admin"
ADMIN_PASS_HASH="$2b$12$....rest_of_your_long_hash_string...."
DB_URL="sqlite:///./secure_logs.db"
(To generate the ADMIN_PASS_HASH, use the hash_pass.py script we created.)

Encryption & Signing Keys: Generate the necessary keys by running these commands in your terminal:

Python

# Command to generate Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# (Save this output to a file named `fernet.key`)

# You will also need to generate ed25519 key pairs and save them
# as `ed25519_private.key` and `ed25519_public.key`
4. Install Dependencies
This project uses pip-tools for robust, secure dependency management.

PowerShell

# Install the tool itself
pip install pip-tools

# Compile the requirements.txt file from requirements.in
pip-compile --generate-hashes requirements.in

# Install all dependencies from the newly generated file
pip install -r requirements.txt
## Running the Application
Start the Backend Server:

PowerShell

# Make sure you are in the /backend directory with your venv active
uvicorn main:app --reload
The API will be available at http://127.0.0.1:8000.

Start the Frontend Application:
Navigate to your frontend directory and run its start command.

Bash

# From the project root
cd ../frontend
npm start
## Project Evolution & Key Updates
This project was iteratively improved with a focus on security, robustness, and modern development practices. The key updates made include:

Secure Dependency Management: Migrated from a simple package list to a full pip-tools workflow. This uses a requirements.in file for direct dependencies and compiles a locked requirements.txt file with cryptographic hashes for a secure, reproducible build.

Enhanced Authentication Security: Upgraded the login system from a plaintext password comparison to a secure, industry-standard bcrypt hashing mechanism using passlib.

Robust Configuration: Replaced basic environment variable loading with Pydantic's Settings class. This provides automatic type-casting, validation, and clear documentation for all required configuration variables.

Modernized Database Practices: Refactored all database interactions to use FastAPI's standard dependency injection pattern (Depends(get_db)). This improves code structure, testability, and session management.

Dedicated Security Event Logging: Implemented a structured JSON logger to explicitly capture critical security events, such as successful and failed login attempts, to a separate app_security_local.log file for analysis.

## License
This project is licensed under the MIT License.
