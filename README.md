# HAProxy Management API

Flask API for managing dynamic HAProxy configuration files.

## Setup

### 1. Install Dependencies

```bash
pip install -r engine/requirements.txt
```

### 2. Environment Variables

Configure these variables in `.env`:

- `API_PORT`: API port (default: `3000`)
- `API_TOKEN_SECRET`: Bearer token used by all protected endpoints
- `CORS_ORIGINS`: `*` or comma-separated origins
- `CORS_SUPPORTS_CREDENTIALS`: `true` or `false`
- `DYNAMIC_CONFIG_DIR`: Dynamic HAProxy config folder
- `SSL_CERT_DIR`: SSL certificate folder
- `TEMPLATE_DIR`: Config template folder
- `HAPROXY_CONFIG`: Base HAProxy config file path

### 3. Run the API

From project root:

```bash
python engine/app.py
```

The API listens on `http://0.0.0.0:3000` by default.

## Authentication

All endpoints require:

```text
Authorization: Bearer <API_TOKEN_SECRET>
```

Unauthorized requests return:

```json
{ "error": "Unauthorized" }
```

## Available Endpoints

### 1) Create Config

- **POST** `/config`
- **Content-Type:** `multipart/form-data`
- **Fields:**
    - `domain` (required)
    - `origin_ip` (required, IPv4 format)
    - `template_id` (optional, default: `default`)
    - `ssl_cert` (optional)
    - `ssl_key` (optional)

Creates `<domain_id>.cfg` in `DYNAMIC_CONFIG_DIR`, validates HAProxy config, and reloads HAProxy. If validation/reload fails, it rolls back the file change.

Success example (`201`):

```json
{
    "status": "success",
    "message": "Config created for domain example.com",
    "domain_id": "example_com"
}
```

### 2) Delete Config by Domain

- **DELETE** `/config/<domain>`

Converts `<domain>` to `<domain_id>`, removes the config file, validates, reloads, and rolls back on failure.

Success example (`200`):

```json
{
    "status": "success",
    "message": "Config deleted for domain example.com",
    "domain_id": "example_com"
}
```

### 3) Update Certificate by Domain

- **PUT** `/config/<domain>/certificate`
- **Content-Type:** `multipart/form-data`
- **Fields:**
    - `ssl_cert` (required)
    - `ssl_key` (required)

Updates `<domain>.pem`, validates HAProxy config, and reloads.

Success example (`200`):

```json
{
    "status": "success",
    "message": "Certificate updated for domain example.com",
    "domain_id": "example_com"
}
```

### 4) List Configs by DOMAIN_ID

- **GET** `/configs`

Lists all `.cfg` files under `DYNAMIC_CONFIG_DIR` with parsed domain/origin metadata.

Success example (`200`):

```json
{
    "total": 1,
    "configs": [
        {
            "domain_id": "example_com",
            "domain": "example.com",
            "domains": ["example.com"],
            "origin_ip": "192.168.1.10",
            "origin_ips": ["192.168.1.10"]
        }
    ]
}
```

### 5) Get Config by DOMAIN_ID

- **GET** `/configs/<domain_id>`

Returns raw config content and parsed metadata.

Success example (`200`):

```json
{
    "domain_id": "example_com",
    "domain": "example.com",
    "origin_ips": ["192.168.1.10"],
    "content": "frontend example_com ..."
}
```

### 6) Update Config by DOMAIN_ID

- **PUT** `/configs/<domain_id>`
- **Content-Type:** one of:
    - `application/json` with `{ "config_content": "..." }`
    - `multipart/form-data` with `config_content`
    - raw text body

Updates `<domain_id>.cfg`, validates HAProxy config, reloads, and rolls back on failure.

Success example (`200`):

```json
{
    "status": "success",
    "message": "Configuration updated successfully.",
    "domain_id": "example_com",
    "domain": "example.com",
    "origin_ips": ["192.168.1.10"]
}
```

### 7) Delete Config by DOMAIN_ID

- **DELETE** `/configs/<domain_id>`

Removes `<domain_id>.cfg` with validate/reload and rollback protection.

Success example (`200`):

```json
{
    "status": "success",
    "message": "Config deleted successfully.",
    "domain_id": "example_com"
}
```

### 8) Validate and Reload HAProxy

- **POST** `/configs/reload`

Validates HAProxy full configuration and reloads only when validation succeeds.

Success example (`200`):

```json
{
    "status": "success",
    "message": "HAProxy configuration validated and reloaded.",
    "validation_output": "Configuration file is valid"
}
```

### 9) Get HAProxy Stats

- **GET** `/logs/stats`

Fetches HAProxy stats from the local stats endpoint using credentials parsed from the configured HAProxy file.

Success (`200`) returns HAProxy stats JSON.

### 10) Get Last Access Logs

- **GET** `/logs/last`

Reads and parses the last 100 lines from `/var/log/access.log`.

Success example (`200`):

```json
{
    "logs": [
        {
            "timestamp": "...",
            "client_ip": "..."
        }
    ]
}
```

## Error Responses

Common error structure:

```json
{ "error": "<message>" }
```

Typical status codes:

- `400` invalid request or HAProxy validation failure
- `401` missing/invalid token
- `404` target config file not found
- `500` internal processing/reload errors

## Notes

- Config files are named `<domain_id>.cfg`.
- `domain_id` is generated by replacing non-alphanumeric chars with `_`, normalizing repeated underscores, and lowercasing.
- There is currently no `/health` endpoint.
