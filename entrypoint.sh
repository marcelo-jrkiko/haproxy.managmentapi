#!/bin/sh
chmod +x /app/engine/tailandredirect.sh

set -e

# Ensure the HAProxy log file exists before rsyslog writes into it.
touch /var/log/access.log

# Start syslog daemon for HAProxy logs.
rsyslogd -f /app/rsyslog-haproxy.conf

# Run log rotation periodically inside the container.
(
	while true; do
		logrotate -s /var/lib/logrotate/status /etc/logrotate.conf
		sleep 86400
	done
) &

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- haproxy "$@"
fi

if [ "$1" = 'haproxy' ]; then
	shift # "haproxy"
	# if the user wants "haproxy", let's add a couple useful flags
	#   -W  -- "master-worker mode" (similar to the old "haproxy-systemd-wrapper"; allows for reload via "SIGUSR2")
	#   -db -- disables background mode
	set -- haproxy -W -db "$@"
fi

# - Starts the API
eval "$(pyenv init -)"
python engine/app.py &

# - Starts the log redirector only if env variable is set
if [ "$START_LOG_REDIRECTOR" = "true" ]; then
	echo "Starting log redirector..."
	/app/engine/tailandredirect.sh &
fi 

exec "$@"