

from datetime import datetime
import logging
import re


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

def is_cert_expiring_soon(expires_at_str, days_threshold):
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        now = datetime.utcnow()
        time_to_expiry = expires_at - now
        return time_to_expiry.total_seconds() < days_threshold * 24 * 3600
    except Exception as e:
        logging.getLogger(__name__).error(f"Error parsing certificate expiry date: {e}")
        return False

def parseAccessLog(log_entry):
    line = log_entry.strip()

    if not line:
        return None
    
    syslog_host = None
    body = line
    # Accept either classic syslog timestamps (e.g. "Jun  3 13:20:13")
    # or RFC3339/ISO-8601 timestamps (e.g. "2026-06-03T13:20:13.516934+00:00").
    syslog_patterns = (
        r'^(?:<\d+>)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<syslog_host>\S+)\s+\S+(?:\[\d+\])?:\s+(?P<body>.*)$',
        r'^(?:<\d+>)?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\s+(?P<syslog_host>\S+)\s+\S+(?:\[\d+\])?:\s+(?P<body>.*)$'
    )
    for syslog_pattern in syslog_patterns:
        syslog_match = re.match(syslog_pattern, line)
        if syslog_match:
            syslog_host = syslog_match.group('syslog_host')
            body = syslog_match.group('body')
            break

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
        
        
    gelf_entry = {
        "version": "1.1",
        "host": host,
        "short_message": request_line[:250],
        "full_message": line,
        "timestamp": log_time.timestamp(),
        "level": 6,
        "_category": "haproxy_httplog",
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

    return gelf_entry