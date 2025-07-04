#!/bin/bash

# n8n Scalable Installation Script for Hetzner Cloud
# Version: 2.0
# OS: Ubuntu 24.04 LTS (Noble Numbat)

set -euo pipefail

# Configuration Variables
DOMAIN_NAME="${DOMAIN_NAME:-n8n.yourdomain.com}"
N8N_VERSION="${N8N_VERSION:-latest}"
NODE_ENV="${NODE_ENV:-production}"
TIMEZONE="${TIMEZONE:-Europe/Paris}"
PRIVATE_NETWORK_IP="${PRIVATE_NETWORK_IP:-10.0.0.10}"
DB_HOST="${DB_HOST:-10.0.0.20}"
REDIS_HOST="${REDIS_HOST:-10.0.0.20}"
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32)}"
N8N_ENCRYPTION_KEY="${N8N_ENCRYPTION_KEY:-$(openssl rand -base64 32)}"
WEBHOOK_URL="${WEBHOOK_URL:-https://$DOMAIN_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Check Ubuntu version
check_ubuntu_version() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            error "This script is designed for Ubuntu. Detected: $ID"
        fi
        
        VERSION_MAJOR=$(echo $VERSION_ID | cut -d. -f1)
        VERSION_MINOR=$(echo $VERSION_ID | cut -d. -f2)
        
        if [[ "$VERSION_MAJOR" -lt 24 ]]; then
            warning "This script is optimized for Ubuntu 24.04 LTS. You are running $VERSION_ID"
            warning "Some features may not work as expected. Continue? (y/n)"
            read -r response
            if [[ "$response" != "y" ]]; then
                exit 1
            fi
        else
            log "Ubuntu $VERSION_ID detected - OK"
        fi
    else
        error "Cannot determine OS version"
    fi
}

# Detect server type based on arguments
SERVER_TYPE="${1:-n8n}"
log "Installing $SERVER_TYPE server..."

# Update system
update_system() {
    log "Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
    
    # Ubuntu 24.04 specific packages
    apt-get install -y \
        curl \
        wget \
        git \
        build-essential \
        python3-pip \
        python3-venv \
        pipx \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        htop \
        btop \
        iotop \
        nethogs \
        vnstat \
        ncdu \
        unattended-upgrades \
        needrestart \
        systemd-timesyncd
    
    # Enable automatic security updates
    dpkg-reconfigure -plow unattended-upgrades
}

# Configure system settings
configure_system() {
    log "Configuring system settings for Ubuntu 24.04..."
    
    # Set timezone
    timedatectl set-timezone $TIMEZONE
    
    # Enable systemd-timesyncd for time synchronization
    systemctl enable systemd-timesyncd
    systemctl start systemd-timesyncd
    
    # Configure systemd-resolved for better DNS performance
    cat > /etc/systemd/resolved.conf.d/99-custom.conf <<EOF
[Resolve]
DNS=1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001
FallbackDNS=8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
DNSStubListener=yes
DNSOverTLS=yes
Cache=yes
CacheFromLocalhost=yes
EOF
    systemctl restart systemd-resolved
    
    # Configure sysctl for performance
    cat > /etc/sysctl.d/99-n8n.conf <<EOF
# Network optimizations for Ubuntu 24.04
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Memory optimizations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1

# File descriptor limits
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Ubuntu 24.04 specific - Enable BPF JIT
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 1
EOF
    sysctl -p /etc/sysctl.d/99-n8n.conf

    # Set ulimits
    cat > /etc/security/limits.d/n8n.conf <<EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65535
* hard nproc 65535
* soft memlock unlimited
* hard memlock unlimited
EOF

    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-n8n.conf <<EOF
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
DefaultLimitMEMLOCK=infinity
EOF
    systemctl daemon-reload
}

# Install Node.js
install_nodejs() {
    log "Installing Node.js 22.x (LTS)..."
    # Ubuntu 24.04 compatible method
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    apt-get install -y nodejs
    
    # Verify installation
    node_version=$(node --version)
    npm_version=$(npm --version)
    log "Node.js $node_version and npm $npm_version installed"
    
    # Install pnpm (faster alternative to npm)
    npm install -g pnpm
    
    # Install PM2 globally with pnpm
    pnpm install -g pm2
    pm2 startup systemd -u root --hp /root
}

# Install PostgreSQL (for DB server)
install_postgresql() {
    log "Installing PostgreSQL 16..."
    
    # Add PostgreSQL APT repository
    echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
    apt-get update -y
    apt-get install -y postgresql-16 postgresql-contrib-16
    
    # Configure PostgreSQL
    systemctl stop postgresql
    
    # Performance tuning
    cat > /etc/postgresql/16/main/conf.d/n8n.conf <<EOF
# Connection settings
listen_addresses = '$PRIVATE_NETWORK_IP,localhost'
max_connections = 200

# Memory settings (for 16GB RAM)
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
work_mem = 20MB

# Checkpoint settings
checkpoint_completion_target = 0.9
wal_buffers = 16MB
min_wal_size = 2GB
max_wal_size = 8GB

# Query tuning
random_page_cost = 1.1
effective_io_concurrency = 200

# Logging
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
EOF

    # Allow connections from private network
    echo "host    all             all             10.0.0.0/16            scram-sha-256" >> /etc/postgresql/16/main/pg_hba.conf
    
    systemctl start postgresql
    systemctl enable postgresql
    
    # Create n8n database and user
    sudo -u postgres psql <<EOF
CREATE USER n8n WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
CREATE DATABASE n8n OWNER n8n;
GRANT ALL PRIVILEGES ON DATABASE n8n TO n8n;
EOF
}

# Install Redis
install_redis() {
    log "Installing Redis..."
    apt-get install -y redis-server
    
    # Configure Redis
    cat > /etc/redis/redis.conf <<EOF
bind $PRIVATE_NETWORK_IP 127.0.0.1
protected-mode yes
port 6379
tcp-backlog 511
timeout 300
tcp-keepalive 300
daemonize yes
supervised systemd
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
maxmemory 2gb
maxmemory-policy allkeys-lru
EOF

    systemctl restart redis-server
    systemctl enable redis-server
}

# Install HAProxy (for load balancer)
install_haproxy() {
    log "Installing HAProxy..."
    apt-get install -y haproxy
    
    # Configure HAProxy
    cat > /etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 4096
    
    # SSL/TLS settings
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!PSK:!DHE:!RSA:!DSS:!aNull:!MD5
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend n8n_frontend
    bind *:80
    bind *:443 ssl crt /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
    redirect scheme https if !{ ssl_fc }
    
    # Headers
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Real-IP %[src]
    
    # ACLs for different paths
    acl is_webhook path_beg /webhook/
    acl is_webhook_test path_beg /webhook-test/
    acl is_websocket hdr(Upgrade) -i websocket
    
    # Use different backends based on path
    use_backend n8n_webhooks if is_webhook
    use_backend n8n_webhooks if is_webhook_test
    use_backend n8n_websockets if is_websocket
    default_backend n8n_main

backend n8n_main
    balance roundrobin
    option httpchk GET /healthz
    http-check expect status 200
    
    # Sticky sessions for UI
    cookie N8NSERVER insert indirect nocache
    
    # Add n8n worker nodes here
    server n8n1 10.0.0.10:5678 check cookie n8n1
    # server n8n2 10.0.0.11:5678 check cookie n8n2

backend n8n_webhooks
    balance roundrobin
    option httpchk GET /healthz
    
    # Webhook workers (no sticky sessions needed)
    server n8n1 10.0.0.10:5678 check
    # server n8n2 10.0.0.11:5678 check

backend n8n_websockets
    balance source
    option http-server-close
    option forceclose
    
    # WebSocket connections
    server n8n1 10.0.0.10:5678 check
    # server n8n2 10.0.0.11:5678 check

# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF

    systemctl restart haproxy
    systemctl enable haproxy
}

# Install n8n
install_n8n() {
    log "Installing n8n..."
    
    # Create n8n user
    useradd -m -s /bin/bash n8n || true
    
    # Install n8n
    if [ "$N8N_VERSION" = "latest" ]; then
        pnpm install -g n8n
    else
        pnpm install -g n8n@$N8N_VERSION
    fi
    
    # Create n8n directories
    mkdir -p /home/n8n/.n8n
    mkdir -p /var/log/n8n
    chown -R n8n:n8n /home/n8n/.n8n
    chown -R n8n:n8n /var/log/n8n
    
    # Create n8n environment file
    cat > /home/n8n/.n8n/n8n.env <<EOF
# Basic settings
NODE_ENV=$NODE_ENV
N8N_PORT=5678
N8N_PROTOCOL=https
N8N_HOST=$DOMAIN_NAME
WEBHOOK_URL=$WEBHOOK_URL

# Database settings
DB_TYPE=postgresdb
DB_POSTGRESDB_HOST=$DB_HOST
DB_POSTGRESDB_PORT=5432
DB_POSTGRESDB_DATABASE=n8n
DB_POSTGRESDB_USER=n8n
DB_POSTGRESDB_PASSWORD=$DB_PASSWORD

# Redis settings
QUEUE_BULL_REDIS_HOST=$REDIS_HOST
QUEUE_BULL_REDIS_PORT=6379
N8N_REDIS_HOST=$REDIS_HOST
N8N_REDIS_PORT=6379

# Execution mode
EXECUTIONS_MODE=queue
QUEUE_HEALTH_CHECK_ACTIVE=true

# Security
N8N_ENCRYPTION_KEY=$N8N_ENCRYPTION_KEY
N8N_USER_MANAGEMENT_DISABLED=false

# Performance settings
N8N_CONCURRENCY_LIMIT=10
N8N_PAYLOAD_SIZE_MAX=16
EXECUTIONS_DATA_PRUNE=true
EXECUTIONS_DATA_MAX_AGE=336
EXECUTIONS_DATA_PRUNE_TIMEOUT=3600

# Metrics
N8N_METRICS=true
N8N_METRICS_PREFIX=n8n_

# Logs
N8N_LOG_LEVEL=info
N8N_LOG_OUTPUT=console
EOF

    chown n8n:n8n /home/n8n/.n8n/n8n.env
    chmod 600 /home/n8n/.n8n/n8n.env
    
    # Create PM2 ecosystem file
    cat > /home/n8n/ecosystem.config.js <<EOF
module.exports = {
  apps: [
    {
      name: 'n8n-main',
      script: 'n8n',
      args: 'start',
      instances: 1,
      exec_mode: 'fork',
      env_file: '/home/n8n/.n8n/n8n.env',
      cwd: '/home/n8n',
      error_file: '/var/log/n8n/error.log',
      out_file: '/var/log/n8n/out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      max_memory_restart: '2G',
      autorestart: true,
      watch: false,
      max_restarts: 10,
      min_uptime: '10s',
    },
    {
      name: 'n8n-worker',
      script: 'n8n',
      args: 'worker',
      instances: 2,
      exec_mode: 'cluster',
      env_file: '/home/n8n/.n8n/n8n.env',
      cwd: '/home/n8n',
      error_file: '/var/log/n8n/worker-error.log',
      out_file: '/var/log/n8n/worker-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      max_memory_restart: '2G',
      autorestart: true,
      watch: false,
      max_restarts: 10,
      min_uptime: '10s',
    },
    {
      name: 'n8n-webhook',
      script: 'n8n',
      args: 'webhook',
      instances: 1,
      exec_mode: 'fork',
      env_file: '/home/n8n/.n8n/n8n.env',
      cwd: '/home/n8n',
      error_file: '/var/log/n8n/webhook-error.log',
      out_file: '/var/log/n8n/webhook-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      max_memory_restart: '1G',
      autorestart: true,
      watch: false,
      max_restarts: 10,
      min_uptime: '10s',
    }
  ]
};
EOF

    chown n8n:n8n /home/n8n/ecosystem.config.js
    
    # Start n8n with PM2
    sudo -u n8n bash -c "cd /home/n8n && pm2 start ecosystem.config.js"
    sudo -u n8n pm2 save
    
    # Create systemd service for PM2
    cat > /etc/systemd/system/pm2-n8n.service <<EOF
[Unit]
Description=PM2 process manager for n8n
After=network.target

[Service]
Type=forking
User=n8n
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
Environment="PM2_HOME=/home/n8n/.pm2"
PIDFile=/home/n8n/.pm2/pm2.pid
Restart=on-failure
RestartSec=5s

ExecStart=/usr/bin/pm2 resurrect
ExecReload=/usr/bin/pm2 reload all
ExecStop=/usr/bin/pm2 kill

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable pm2-n8n
    systemctl start pm2-n8n
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (customize port if needed)
    ufw allow 22/tcp comment 'SSH'
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow HAProxy stats (only from private network)
    ufw allow from 10.0.0.0/16 to any port 8404 comment 'HAProxy Stats'
    
    # Allow n8n port from private network only
    ufw allow from 10.0.0.0/16 to any port 5678 comment 'n8n'
    
    # Allow PostgreSQL from private network
    ufw allow from 10.0.0.0/16 to any port 5432 comment 'PostgreSQL'
    
    # Allow Redis from private network
    ufw allow from 10.0.0.0/16 to any port 6379 comment 'Redis'
    
    # Enable firewall
    echo "y" | ufw enable
}

# Configure fail2ban
configure_fail2ban() {
    log "Configuring fail2ban..."
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 10.0.0.0/16

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3

[n8n-auth]
enabled = true
port = http,https
filter = n8n-auth
logpath = /var/log/n8n/*.log
maxretry = 5
findtime = 600
bantime = 3600
EOF

    # Create n8n filter
    cat > /etc/fail2ban/filter.d/n8n-auth.conf <<EOF
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Unauthorized access attempt.*from <HOST>.*$
ignoreregex =
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
}

# Install SSL certificate
install_ssl() {
    log "Installing SSL certificate..."
    
    # Install certbot
    apt-get install -y certbot
    
    # Get certificate (make sure domain is pointing to server)
    certbot certonly --standalone -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME
    
    # Create renewal script
    cat > /etc/cron.daily/certbot-renew <<EOF
#!/bin/bash
certbot renew --quiet --post-hook "systemctl reload haproxy"
EOF
    chmod +x /etc/cron.daily/certbot-renew
}

# Configure backups
configure_backups() {
    log "Configuring backups..."
    
    # Create backup directory
    mkdir -p /backup/n8n
    
    # Create backup script
    cat > /usr/local/bin/n8n-backup.sh <<'EOF'
#!/bin/bash

BACKUP_DIR="/backup/n8n"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

# Backup database
sudo -u postgres pg_dump n8n | gzip > $BACKUP_DIR/n8n_db_$DATE.sql.gz

# Backup n8n data
tar -czf $BACKUP_DIR/n8n_data_$DATE.tar.gz /home/n8n/.n8n/

# Backup configuration
tar -czf $BACKUP_DIR/n8n_config_$DATE.tar.gz /etc/haproxy/ /etc/redis/ /home/n8n/ecosystem.config.js

# Clean old backups
find $BACKUP_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Optional: Sync to Hetzner Backup Space
# rsync -av --delete $BACKUP_DIR/ u123456@u123456.your-storagebox.de:/backups/n8n/
EOF
    chmod +x /usr/local/bin/n8n-backup.sh
    
    # Add to crontab
    echo "0 2 * * * /usr/local/bin/n8n-backup.sh" | crontab -
}

# Monitoring setup
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Install modern monitoring stack for Ubuntu 24.04
    # Install Prometheus Node Exporter
    ARCH=$(dpkg --print-architecture)
    wget https://github.com/prometheus/node_exporter/releases/latest/download/node_exporter-1.8.2.linux-${ARCH}.tar.gz
    tar xvf node_exporter-*.tar.gz
    sudo cp node_exporter-*/node_exporter /usr/local/bin/
    rm -rf node_exporter-*
    
    # Create systemd service for node_exporter
    cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/node_exporter \
    --collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($|/) \
    --collector.netclass.ignored-devices=^(veth.*) \
    --collector.diskstats.ignored-devices=^(ram|loop|fd|dm-)\d+$ \
    --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Create directory for custom metrics
    mkdir -p /var/lib/node_exporter/textfile_collector
    
    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter
    
    # Install vector for log aggregation (Ubuntu 24.04 compatible)
    curl -L https://repositories.timber.io/public/vector/cfg/setup/bash.deb.sh | bash
    apt-get install -y vector
    
    # Configure vector for n8n logs
    cat > /etc/vector/vector.toml <<EOF
[sources.n8n_logs]
type = "file"
include = ["/var/log/n8n/*.log"]
read_from = "end"

[transforms.parse_n8n]
type = "remap"
inputs = ["n8n_logs"]
source = '''
. = parse_json!(.message)
.timestamp = now()
'''

[sinks.console]
type = "console"
inputs = ["parse_n8n"]
encoding.codec = "json"
EOF

    systemctl enable vector
    systemctl start vector
    
    # Create health check endpoint
    cat > /usr/local/bin/n8n-health.sh <<'EOF'
#!/bin/bash
# Enhanced health check for Ubuntu 24.04
set -e

# Check n8n main process
if ! curl -sf http://localhost:5678/healthz > /dev/null; then
    echo "n8n main process is not responding"
    exit 1
fi

# Check database connection
if ! pg_isready -h $DB_HOST -p 5432 > /dev/null 2>&1; then
    echo "Database is not reachable"
    exit 1
fi

# Check Redis connection
if ! redis-cli -h $REDIS_HOST ping > /dev/null 2>&1; then
    echo "Redis is not reachable"
    exit 1
fi

echo "All systems operational"
exit 0
EOF
    chmod +x /usr/local/bin/n8n-health.sh
}

# Performance tuning
performance_tuning() {
    log "Applying performance tuning..."
    
    # Disable transparent huge pages
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
    
    # Add to rc.local
    cat > /etc/rc.local <<'EOF'
#!/bin/bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
exit 0
EOF
    chmod +x /etc/rc.local
    
    # CPU governor
    apt-get install -y cpufrequtils
    echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
    systemctl restart cpufrequtils
}

# Main installation flow
main() {
    log "Starting n8n installation for $SERVER_TYPE..."
    
    check_ubuntu_version
    update_system
    configure_system
    configure_firewall
    configure_fail2ban
    
    case "$SERVER_TYPE" in
        "loadbalancer")
            install_haproxy
            install_ssl
            ;;
        "database")
            install_postgresql
            install_redis
            configure_backups
            ;;
        "n8n")
            install_nodejs
            install_n8n
            setup_monitoring
            performance_tuning
            ;;
        "all")
            # Install everything on one server (for testing)
            install_postgresql
            install_redis
            install_nodejs
            install_n8n
            install_haproxy
            install_ssl
            configure_backups
            setup_monitoring
            performance_tuning
            ;;
        *)
            error "Unknown server type. Use: loadbalancer, database, n8n, or all"
            ;;
    esac
    
    log "Installation completed successfully!"
    log "Database password: $DB_PASSWORD"
    log "N8N encryption key: $N8N_ENCRYPTION_KEY"
    log ""
    log "Next steps:"
    log "1. Save the passwords above in a secure location"
    log "2. Configure DNS to point $DOMAIN_NAME to this server"
    log "3. Access n8n at https://$DOMAIN_NAME"
    log "4. Check HAProxy stats at http://$PRIVATE_NETWORK_IP:8404/stats"
    log ""
    log "To add more n8n workers:"
    log "1. Run this script on new server with: ./install.sh n8n"
    log "2. Update HAProxy configuration to include new server"
    log "3. Reload HAProxy: systemctl reload haproxy"
}

# Run main function
main "$@"
