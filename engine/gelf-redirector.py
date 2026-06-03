import time
import os
import socket
import requests
import sys

import urllib 
import urllib3
import re
from datetime import datetime
import argparse 
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
import logging
import json
from slugify import slugify
import utils

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
parser.add_argument('--gelf_auth_type', type=str, choices=['none', 'header', 'bearer'], default=None, help='Authentication type for GELF HTTP endpoint. Can also be set via GELF_AUTH_TYPE environment variable')
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

def get_gelf_server_hostname():
    """Extract hostname from GELF_HTTP_URL to prevent infinite logging loops."""
    try:
        parsed = urllib.parse.urlparse(GELF_HTTP_URL)
        return parsed.hostname or parsed.netloc.split(':')[0]
    except Exception as e:
        logging.warning(f"Failed to parse GELF_HTTP_URL for hostname extraction: {e}")
        return None
    
def parseAccessLog(log_entry):
    line = log_entry.strip()

    gelf_entry = utils.parseAccessLog(line)
    if gelf_entry is None:
        return None

    host = gelf_entry.get("host")
    gelf_entry["_instance"] = INSTANCE
    gelf_entry["_category"] = "haproxy_httplog"
    gelf_entry["_client"] = CLIENT
    gelf_entry["_test"] = f"{IS_TEST_MESSAGE}"
    
    if CLIENT == 'from-host':
        gelf_entry["_client"] = slugify(host) if host else "unknown"

    return gelf_entry

def send_to_graylog(message):
    gelf_message = parseAccessLog(message)           
    
    if(gelf_message is None):
        logging.error(f"[ERROR] Failed to parse the log entry: {message}")
        return 
    
    # Prevent infinite logging loops: ignore logs from the GELF server itself
    gelf_hostname = get_gelf_server_hostname()
    log_host = gelf_message.get("host", "")
    if gelf_hostname and log_host and gelf_hostname.lower() == log_host.lower():
        logging.info(f"[INFO] Ignoring log from GELF server host '{log_host}' to prevent infinite loop")
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


