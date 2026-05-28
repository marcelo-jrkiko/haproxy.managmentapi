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
    
def _safe_int(value, default=0):
    try:
        if value in (None, "", "-"):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_header_value(headers_blob, header_name):
    if not headers_blob or headers_blob == '-':
        return None
    # Captured headers are usually pipe-separated in HAProxy logs.
    for part in headers_blob.split('|'):
        item = part.strip()
        if item.lower().startswith(f"{header_name.lower()}:"):
            return item.split(':', 1)[1].strip()
    return None

def parseAccessLog(log_entry):
    line = log_entry.strip()

    if not line:
        return None
    
    syslog_host = None
    body = line
    syslog_match = re.match(
        r'^(?:<\d+>)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<syslog_host>\S+)\s+\S+(?:\[\d+\])?:\s+(?P<body>.*)$',
        line
    )
    if syslog_match:
        syslog_host = syslog_match.group('syslog_host')
        body = syslog_match.group('body')

    pattern = re.compile(
        r'^(?P<client_ip>\S+):(?P<client_port>\d+)\s+'
        r'\[(?P<accept_date>[^\]]+)\]\s+'
        r'(?P<frontend_name>\S+)\s+'
        r'(?P<backend_server>\S+)\s+'
        r'(?P<timers>\S+)\s+'
        r'(?P<status_code>\d+)\s+'
        r'(?P<bytes_read>\S+)\s+'
        r'(?P<captured_request_cookie>\S+)\s+'
        r'(?P<captured_response_cookie>\S+)\s+'
        r'(?P<termination_state>\S+)\s+'
        r'(?P<connections>\S+)\s+'
        r'(?P<queues>\S+)'
        r'(?:\s+(?P<rest>.*))?$'
    )
    match = pattern.match(body)
    if not match:
        logging.error(f"[ERROR] Could not parse HAProxy httplog line: {line}")
        return None

    groups = match.groupdict()

    backend_name, server_name = groups['backend_server'], None
    if '/' in groups['backend_server']:
        backend_name, server_name = groups['backend_server'].split('/', 1)

    tq, tw, tc, tr, ta = (groups.get('timers') or '0/0/0/0/0').split('/')[:5]
    actconn, feconn, beconn, srv_conn, retries = (groups.get('connections') or '0/0/0/0/0').split('/')[:5]
    srv_queue, backend_queue = (groups.get('queues') or '0/0').split('/')[:2]

    request_line = '-'
    captured_request_headers = None
    captured_response_headers = None
    rest = groups.get('rest') or ''

    req_res_match = re.search(r'\{(?P<req_headers>.*?)\}\s+\{(?P<res_headers>.*?)\}\s+"(?P<request>.*)"\s*$', rest)
    if req_res_match:
        captured_request_headers = req_res_match.group('req_headers')
        captured_response_headers = req_res_match.group('res_headers')
        request_line = req_res_match.group('request')
    else:
        req_only_match = re.search(r'\{(?P<req_headers>.*?)\}\s+"(?P<request>.*)"\s*$', rest)
        if req_only_match:
            captured_request_headers = req_only_match.group('req_headers')
            request_line = req_only_match.group('request')
        else:
            request_match = re.search(r'"(?P<request>.*)"\s*$', rest)
            if request_match:
                request_line = request_match.group('request')

    host = _extract_header_value(captured_request_headers, 'host') or syslog_host or 'unknown'
    http_referer = _extract_header_value(captured_request_headers, 'referer')
    http_user_agent = _extract_header_value(captured_request_headers, 'user-agent')

    log_time = None
    accept_date_raw = (groups.get('accept_date') or '').strip()
    for date_fmt in ("%d/%b/%Y:%H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S"):
        try:
            log_time = datetime.strptime(accept_date_raw, date_fmt)
            break
        except ValueError:
            continue
    if log_time is None:
        log_time = datetime.utcnow()

    logging.info(
        f"{request_line[:120]} - {log_time} - {groups.get('status_code', 0)} - "
        f"{groups.get('client_ip', '-')} - {groups.get('bytes_read', 0)} - "
        f"{http_user_agent or '-'} - {http_referer or '-'}"
    )

    gelf_entry = {
        "version": "1.1",
        "host": host,
        "short_message": request_line[:250],
        "full_message": line,
        "timestamp": log_time.timestamp(),
        "level": 6,
        "_instance": INSTANCE,
        "_category": "haproxy_httplog",
        "_client": CLIENT,
        "_test": f"{IS_TEST_MESSAGE}",
        "_client_ip": groups.get('client_ip'),
        "_client_port": _safe_int(groups.get('client_port')),
        "_accept_date": accept_date_raw,
        "_frontend_name": groups.get('frontend_name'),
        "_backend_name": backend_name,
        "_server_name": server_name,
        "_time_request": _safe_int(tq),
        "_time_waiting": _safe_int(tw),
        "_time_connecting": _safe_int(tc),
        "_time_response": _safe_int(tr),
        "_time_total": _safe_int(ta),
        "_status_code": _safe_int(groups.get('status_code')),
        "_bytes_read": _safe_int(groups.get('bytes_read')),
        "_termination_state": groups.get('termination_state'),
        "_captured_request_cookie": groups.get('captured_request_cookie'),
        "_captured_response_cookie": groups.get('captured_response_cookie'),
        "_actconn": _safe_int(actconn),
        "_feconn": _safe_int(feconn),
        "_beconn": _safe_int(beconn),
        "_srv_conn": _safe_int(srv_conn),
        "_retries": _safe_int(retries),
        "_srv_queue": _safe_int(srv_queue),
        "_backend_queue": _safe_int(backend_queue),
        "_http_request": request_line,
        "_http_response": captured_response_headers,
        "_http_referer": http_referer,
        "_http_user_agent": http_user_agent,
        "_captured_request_headers": captured_request_headers,
        "_captured_response_headers": captured_response_headers
    }

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


