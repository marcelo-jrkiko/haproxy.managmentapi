# HAProxy Management API

A Flask API for managing HAProxy configuration files dynamically.

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Variables
The following variables are configured in `.env`:
- `API_PORT`: Port where the API runs (default: 3000)
- `API_TOKEN_SECRET`: Token for API authentication
- `DYNAMIC_CONFIG_DIR`: Directory where config files are stored (default: ./dynamic_config)

### 3. Run the API
```bash
python app.py
```

The API will start on `http://0.0.0.0:3000`

## API Endpoints

### 1. Create Config File
**POST** `/config`

Creates a new HAProxy configuration file for a domain.

**Headers:**
```
Authorization: Bearer <API_TOKEN_SECRET>
Content-Type: application/json
```

**Request Body:**
```json
{
    "domain": "example.com",
    "origin_ip": "192.168.1.100"
}
```

**Response (201 Created):**
```json
{
    "status": "success",
    "message": "Config created for domain example.com",
    "domain_id": "example_com",
    "filename": "example_com.cfg",
    "path": "./dynamic_config/example_com.cfg"
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/config \
  -H "Authorization: Bearer S3x7U9t10u4sCTHsfXjj7Lo0dqGYkTTL" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "origin_ip": "192.168.1.100"
  }'
```

### 2. Delete Config File
**DELETE** `/config/<domain>`

Removes the HAProxy configuration file for a domain.

**Headers:**
```
Authorization: Bearer <API_TOKEN_SECRET>
```

**URL Parameter:**
- `domain`: The domain name (e.g., example.com)

**Response (200 OK):**
```json
{
    "status": "success",
    "message": "Config deleted for domain example.com",
    "domain_id": "example_com",
    "filename": "example_com.cfg"
}
```

**Example using curl:**
```bash
curl -X DELETE http://localhost:3000/config/example.com \
  -H "Authorization: Bearer S3x7U9t10u4sCTHsfXjj7Lo0dqGYkTTL"
```

### 3. Health Check
**GET** `/health`

Check if the API is running.

**Response (200 OK):**
```json
{
    "status": "ok"
}
```

## Features

- **Template-based Config Generation**: Uses `domain_config.template` to generate HAProxy configs
- **Domain ID Generation**: Automatically creates sanitized domain IDs from domain names
- **Token Authentication**: All endpoints (except /health) require Bearer token authentication
- **Dynamic Directory**: Config files are stored in the configured `DYNAMIC_CONFIG_DIR`
- **Input Validation**: Validates domain names and IP addresses

## Config File Naming

Config files are named based on a sanitized version of the domain:
- `example.com` → `example_com.cfg`
- `sub-domain.example.com` → `sub_domain_example_com.cfg`

## Error Responses

### 400 Bad Request
```json
{
    "error": "Missing required fields: domain, origin_ip"
}
```

### 401 Unauthorized
```json
{
    "error": "Unauthorized"
}
```

### 404 Not Found
```json
{
    "error": "Config file not found for domain example.com"
}
```

### 500 Internal Server Error
```json
{
    "error": "Failed to write config file: <error details>"
}
```

## Generated Config Structure

Generated config files follow this structure:
```
frontend <domain_id>
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }

    use_backend <domain_id>_backend if { req_ssl_sni -i <domain> }
    default_backend <domain_id>_backend

backend <domain_id>_backend
    mode tcp
    server app <origin_ip>:443
```
