#!/bin/bash
cd /app/
eval "$(pyenv init -)"
pyenv global 3.12.0 
FILE="/var/log/access.log"

until [[ -e "$FILE" ]]; do
  sleep 2
done

echo "$FILE found, starting to tail."

tail -F "$FILE" | while IFS= read -r message; do
  echo "$message" | /usr/bin/python3 /app/engine/gelf-redirector.py --log_path stdin --instance "$LOG_REDIRECTOR_INSTANCE" --client "from-host" --gelf_http_url "$GELF_HTTP_URL" --gelf_auth_type "$GELF_AUTH_TYPE" --gelf_auth_token "$GELF_AUTH_TOKEN"
done

