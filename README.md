# E2E-chat
This reposity contains project for Network Security course at UNICA

## Prerequisites

- Python 3.10+  
- Docker & Docker Compose  
- pip

---

## Setup Instructions Server

Run the following commands to generate SSL certificates, populate the environment file, start Docker services, create a Python virtual environment, install dependencies, and initialize the database:

### 1. Change to server directory
```bash
cd server
```

### 2. Create a private key and self-signed certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -addext "subjectAltName=DNS:localhost"
```
### 3. Copy and populate the .env file
```bash
cp .env.example .env
nano .env  # Edit with your variables
```

### 4. Start Docker services
```bash
docker compose up -d
```
### 5. Create and activate a Python virtual environment
```bash
python3 -m venv ./test-server-env
source test-server-env/bin/activate
```

### 6. Install Python dependencies
```bash
pip3 install -r requirements.txt
```

### 7. Initialize the database
```bash
python3 init_db.py
```

### 8. Start server
```bash
python3 server.py
```

### 9. PgAdmin
I also deployed PgAdmin, so you can look at database data. To do so, visit http://localhost:5050/ and login using passwords from .env, then add server using data from .env and `postgres` as domain
## Setup Instructions Client

Run the following commands to generate SSL certificates, populate the environment file, start Docker services, create a Python virtual environment, install dependencies, and initialize the database:

### 1. Change to server directory
```bash
cd client
```

### 2. Copy and populate the .env file
```bash
cp .env.example .env
nano .env  # Edit with your variables
```

### 3. Create and activate a Python virtual environment
```bash
python3 -m venv ./test-client-env
source test-client-env/bin/activate
```

### 4. Install Python dependencies
```bash
pip3 install -r requirements.txt
```

### 5. Start client (just test right now)
```bash
python3 crypto_client.py
```

## Termination instructions server

### 1. End server
CTRL-c in terminal with server

### 2. Deactivate virtual enviroment
```bash
deactivate
```

### 3. Shut down containers
```bash
docker compose down
```

### 4. Remove containers with volumes (not required)
```bash
docker compose rm -v
```

## Termination instructions Client

### 1. Deactivate virtual enviroment
```bash
deactivate
```
