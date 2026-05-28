FROM haproxy:3.3.8-trixie

# change user to root to install dependencies
USER root

# Install dependencies
RUN apt-get update && \
    apt-get install build-essential gdb lcov pkg-config \
      libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
      libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
      lzma tk-dev uuid-dev zlib1g-dev libzstd-dev \
    inetutils-inetd curl git rsyslog logrotate -y 

# Install pyenv and Python 3.12.0
ENV PYENV_ROOT="/root/.pyenv"
ENV PATH="$PYENV_ROOT/bin:$PATH"

RUN curl -fsSL https://pyenv.run | bash && \
        eval "$(pyenv init -)" && \
        pyenv install 3.12.0 && \
        pyenv global 3.12.0 && \
        python -m pip install --no-cache-dir requests python-dotenv gitpython watchdog 

WORKDIR /app
COPY . /app/

# Configure rsyslog and log rotation for HAProxy access logs.
RUN cp /app/rsyslog-haproxy.conf /etc/rsyslog.d/49-haproxy.conf && \
    cp /app/logrotate-haproxy.conf /etc/logrotate.d/haproxy-access

# Install Python dependencies
RUN eval "$(pyenv init -)" && \
    pyenv global 3.12.0 && \
    python -m pip install --no-cache-dir -r engine/requirements.txt

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER root

EXPOSE 3000
ENTRYPOINT [ "/entrypoint.sh" ]