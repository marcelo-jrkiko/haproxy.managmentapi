import time
import os
import socket
import requests
import sys 
import urllib3
import re
from datetime import datetime
import argparse 
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
import logging
import json
from slugify import slugify

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
urllib3.disable_warnings()

## Arg Parser
parser = argparse.ArgumentParser(description="Apache2 Log GelfHttp Sender")
parser.add_argument('--client', type=str, help='Sets the client field of the log event. \r\n\t Use "from-host" to slugify the host field from the log and use it as client')
parser.add_argument('--instance', type=str, help='Sets the instance field of the log event')
parser.add_argument('--log_path', type=str, help='Log path to monitor for new log entries. stdin can also be used to read from a pipe')
parser.add_argument('--test', type=bool, help='Flags the message as a test')
parser.add_argument('--logger', type=str, help='Path to a file where the script will log its operations. If not set, logs will only be printed to stdout')
parser.add_argument('--gelf_http_url', type=str, help='URL of the GELF HTTP endpoint to send log messages to. Can also be set via GELF_HTTP_URL environment variable' )
parser.add_argument('--gelf_auth_type', type=str, choices=['none', 'header', 'bearer'], default='none', help='Authentication type for GELF HTTP endpoint. Can also be set via GELF_AUTH_TYPE environment variable')
parser.add_argument('--gelf_auth_token', type=str, help='Authentication token for GELF HTTP endpoint. Can also be set via GELF_AUTH_TOKEN environment variable')    
args = parser.parse_args()

# === GELF Configuration from Env Vars or Args ===
GELF_HTTP_URL = args.gelf_http_url or os.getenv('GELF_HTTP_URL', 'http://graylog:12201/gelf')  # Default to http://graylog:12201/gelf if not set
GELF_AUTH_TYPE = args.gelf_auth_type or os.getenv('GELF_AUTH_TYPE', 'none')  # none, header, bearer
GELF_AUTH_TOKEN = args.gelf_auth_token or os.getenv('GELF_AUTH_TOKEN', '')  # Token for header or bearer auth

# === Main Configuration from Args ===
LOG_PATH = args.log_path or os.getenv('LOG_PATH', 'stdin')  # Default to stdin if not set
CLIENT = args.client or os.getenv('CLIENT', 'unknown')  # Default to 'unknown' if not set
INSTANCE = args.instance or os.getenv('INSTANCE', 'unknown')  # Default to 'unknown' if not set
IS_TEST_MESSAGE = args.test or (os.getenv('TEST', 'false').lower() == 'true')  # Convert env var to boolean

if(args.logger != None and len(args.logger) > 0):
    logging.getLogger().addHandler(logging.FileHandler(args.logger))
    
# === Helper Functions ===

def parseAccessLog(log_entry):
    log_object = json.loads(log_entry)

    accept_date_raw = str(log_object.get('accept_date', '')).replace('[', '').replace(']', '').strip()
    log_time = None
    for date_fmt in ("%d/%b/%Y:%H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            log_time = datetime.strptime(accept_date_raw, date_fmt)
            break
        except ValueError:
            continue

    if log_time is None:
        log_time = datetime.utcnow()

    logging.info(
        f"{log_object.get('http_request', '-')[:120]} - {log_time} - "
        f"{log_object.get('status_code', 0)} - {log_object.get('client_ip', '-')} - "
        f"{log_object.get('bytes_read', 0)} - {log_object.get('http_user_agent', '-')} - "
        f"{log_object.get('http_referer', '-')}"
    )

    gelf_entry = {
        "version": "1.1",
        "host": log_object.get("host", "unknown"),
        "short_message": str(log_object.get("http_request", "-") or "-")[:250],
        "full_message": log_entry,
        "timestamp": log_time.timestamp(),
        "level": 6,
        "_instance": INSTANCE,
        "_category": "haproxy_access",
        "_client": CLIENT,
        "_test": f"{IS_TEST_MESSAGE}",
        "_client_ip": log_object.get("client_ip"),
        "_client_port": int(log_object.get("client_port", 0) or 0),
        "_frontend_name": log_object.get("frontend_name"),
        "_backend_name": log_object.get("backend_name"),
        "_server_name": log_object.get("server_name"),
        "_time_request": int(log_object.get("time_request", 0) or 0),
        "_time_waiting": int(log_object.get("time_waiting", 0) or 0),
        "_time_connecting": int(log_object.get("time_connecting", 0) or 0),
        "_time_response": int(log_object.get("time_response", 0) or 0),
        "_time_total": int(log_object.get("time_total", 0) or 0),
        "_status_code": int(log_object.get("status_code", 0) or 0),
        "_bytes_read": int(log_object.get("bytes_read", 0) or 0),
        "_termination_state": log_object.get("termination_state"),
        "_actconn": int(log_object.get("actconn", 0) or 0),
        "_feconn": int(log_object.get("feconn", 0) or 0),
        "_beconn": int(log_object.get("beconn", 0) or 0),
        "_srv_conn": int(log_object.get("srv_conn", 0) or 0),
        "_retries": int(log_object.get("retries", 0) or 0),
        "_srv_queue": int(log_object.get("srv_queue", 0) or 0),
        "_backend_queue": int(log_object.get("backend_queue", 0) or 0),
        "_http_request": log_object.get("http_request"),
        "_http_response": log_object.get("http_response"),
        "_http_referer": log_object.get("http_referer"),
        "_http_user_agent": log_object.get("http_user_agent")
    }

    if CLIENT == 'from-host':  # Slugify host prefix as client
        gelf_entry["_client"] = slugify(log_object.get("host", "").split('.')[0]) if log_object.get("host") else "unknown"

    return gelf_entry

def send_to_graylog(message):
    gelf_message = parseAccessLog(message)           
    
    if(gelf_message is None):
        logging.error(f"[ERROR] Failed to parse the log entry: {message}")
        return 

    try:
        headers = {
            'Content-Type': 'application/json'
        }
        
        if GELF_AUTH_TYPE == 'header' and GELF_AUTH_TOKEN:
            headers['X-API-Key'] = GELF_AUTH_TOKEN
        elif GELF_AUTH_TYPE == 'bearer' and GELF_AUTH_TOKEN:
            headers['Authorization'] = f'Bearer {GELF_AUTH_TOKEN}'
        
        response = requests.post(GELF_HTTP_URL, json=gelf_message, headers=headers, verify=False, timeout=3)
        response.raise_for_status()
    except requests.RequestException as e:
        logging.error(f"[ERROR] Failed to send to Graylog: {e}")

def monitor_log_file(file_path):
    with open(file_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        while True:
            line = log_file.readline()
            if line:
                logging.info(f"[INFO] New log event data: {line.strip()}")
                send_to_graylog(line.strip())
            else:
                time.sleep(0.1)  # Sleep briefly to avoid busy waiting

try:
    logging.info(f"[INFO] New log event")
    
    if LOG_PATH == 'stdin':
        logging.info(f"[INFO] Reading log data from stdin")        
        logData = sys.stdin.read()
        logging.info(f"[INFO] New log event data: {logData}")
        send_to_graylog(logData)
    else:
        logging.info(f"[INFO] Monitoring log file: {LOG_PATH}")
        monitor_log_file(LOG_PATH)
except Exception as err:
    logging.error(f"[ERROR] Failed to retrieve the log: {err=}")


