#!/bin/bash

#########################################
# n8n Installation Script for KeyBuzz
# Version: 2.0
# OS: Ubuntu 24.04 LTS
# Author: KeyBuzz
# Repository: https://github.com/KeyBuzz/n8n
#########################################

set -euo pipefail

# Configuration par défaut
DOMAIN_NAME="${DOMAIN_NAME:-n8n.keybuzz.io}"
EMAIL="${EMAIL:-ludovic@keybuzz.pro}"
N8N_VERSION="${N8N_VERSION:-latest}"
NODE_ENV="production"
TIMEZONE="${TIMEZONE:-Europe/Paris}"
PRIVATE_IP="${PRIVATE_IP:-10.0.0.2}"
PUBLIC_IP="${PUBLIC_IP:-195.201.98.217}"

# Génération des mots de passe
DB_PASSWORD=$(openssl rand -base64 32)
N8N_ENCRYPTION_KEY=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logo KeyBuzz
print_logo() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════╗
║        KeyBuzz n8n Installation       ║
║         https://keybuzz.io            ║
╚═══════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Fonctions de log
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Vérification des droits root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en root"
    fi
}

# Vérification Ubuntu 24.04
check_ubuntu() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "24.04" ]]; then
            warning "Ce script est optimisé pour Ubuntu 24.04 LTS"
            warning "Version détectée : $ID $VERSION_ID"
            read -p "Continuer quand même ? (o/n) " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Oo]$ ]] && exit 1
        fi
    fi
}

# Mise à jour du système
update_system() {
    log "Mise à jour du système..."
    apt-get update -y
    apt-get upgrade -y
    apt-get install -y \
        curl wget git htop iotop vnstat \
        build-essential software-properties-common \
        apt-transport-https ca-certificates gnupg lsb-release \
        ufw fail2ban unattended-upgrades \
        nginx certbot python3-certbot-nginx
}

# Configuration système
configure_system() {
    log "Configuration système optimisée pour 4GB RAM..."
    
    # Hostname
    hostnamectl set-hostname n8n-keybuzz
    
    # Timezone
    timedatectl set-timezone $TIMEZONE
    
    # Swap
    if [ ! -f /swapfile ]; then
        fallocate -l 4G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    # Optimisations système
    cat > /etc/sysctl.d/99-n8n-keybuzz.conf <<EOF
# Network
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# Memory (4GB RAM)
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# File handles
fs.file-max = 100000
fs.inotify.max_user_watches = 524288
EOF
    sysctl -p /etc/sysctl.d/99-n8n-keybuzz.conf
}

# Installation Node.js
install_nodejs() {
    log "Installation Node.js 20.x LTS..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    npm install -g pm2
    info "Node.js $(node --version) installé"
}

# Installation PostgreSQL
install_postgresql() {
    log "Installation PostgreSQL 16..."
    echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
    apt-get update -y
    apt-get install -y postgresql-16 postgresql-contrib-16
    
    # Configuration
    cat > /etc/postgresql/16/main/conf.d/n8n.conf <<EOF
listen_addresses = 'localhost'
max_connections = 100
shared_buffers = 1GB
effective_cache_size = 3GB
maintenance_work_mem = 256MB
work_mem = 10MB
random_page_cost = 1.1
EOF
    
    systemctl restart postgresql
    
    # Créer la base
    sudo -u postgres psql <<EOF
CREATE USER n8n WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
CREATE DATABASE n8n OWNER n8n;
GRANT ALL PRIVILEGES ON DATABASE n8n TO n8n;
EOF
}

# Installation Redis
install_redis() {
    log "Installation Redis..."
    apt-get install -y redis-server
    
    # Configuration Redis avec limite mémoire
    cat > /etc/redis/redis.conf <<EOF
bind 127.0.0.1
protected-mode yes
port 6379
timeout 300
tcp-keepalive 300
daemonize yes
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
maxmemory 512mb
maxmemory-policy allkeys-lru
requirepass $REDIS_PASSWORD
EOF
    
    systemctl restart redis-server
    systemctl enable redis-server
}

# Installation n8n
install_n8n() {
    log "Installation n8n..."
    
    # Créer utilisateur
    useradd -m -s /bin/bash n8n || true
    
    # Installer n8n
    npm install -g n8n@$N8N_VERSION
    
    # Créer les répertoires
    mkdir -p /home/n8n/.n8n
    mkdir -p /var/log/n8n
    chown -R n8n:n8n /home/n8n/.n8n /var/log/n8n
    
    # Configuration n8n
    cat > /home/n8n/.n8n/config.json <<EOF
{
  "database": {
    "type": "postgresdb",
    "postgresdb": {
      "host": "localhost",
      "port": 5432,
      "database": "n8n",
      "user": "n8n",
      "password": "$DB_PASSWORD"
    }
  },
  "executions": {
    "pruneData": true,
    "pruneDataMaxAge": 168
  },
  "queue": {
    "bull": {
      "redis": {
        "host": "localhost",
        "port": 6379,
        "password": "$REDIS_PASSWORD"
      }
    }
  },
  "generic": {
    "timezone": "$TIMEZONE"
  },
  "security": {
    "encryptionKey": "$N8N_ENCRYPTION_KEY"
  }
}
EOF
    
    chmod 600 /home/n8n/.n8n/config.json
    chown n8n:n8n /home/n8n/.n8n/config.json
    
    # PM2 config
    cat > /home/n8n/ecosystem.config.js <<EOF
module.exports = {
  apps: [{
    name: 'n8n',
    script: '/usr/bin/n8n',
    args: 'start',
    cwd: '/home/n8n',
    env: {
      HOME: '/home/n8n',
      N8N_PORT: '5678',
      N8N_RUNNERS_ENABLED: 'true',
      NODE_ENV: 'production',
      N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: 'true'
    },
    error_file: '/var/log/n8n/error.log',
    out_file: '/var/log/n8n/out.log',
    max_memory_restart: '2G',
    autorestart: true
  }]
}
EOF
    
    chown n8n:n8n /home/n8n/ecosystem.config.js
    
    # Démarrer n8n
    sudo -u n8n bash -c 'cd /home/n8n && pm2 start ecosystem.config.js'
    sudo -u n8n pm2 save
    sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u n8n --hp /home/n8n
}

# Configuration Nginx
configure_nginx() {
    log "Configuration Nginx..."
    
    cat > /etc/nginx/sites-available/n8n <<'EOF'
limit_req_zone $binary_remote_addr zone=n8n_limit:10m rate=10r/s;

server {
    listen 80;
    listen [::]:80;
    server_name n8n.keybuzz.io;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/n8n /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t && systemctl restart nginx
}

# Configuration SSL
configure_ssl() {
    log "Configuration SSL avec Let's Encrypt..."
    certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email $EMAIL --redirect
}

# Configuration firewall
configure_firewall() {
    log "Configuration du firewall..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 2222/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 8080/tcp
    echo "y" | ufw enable
}

# Configuration backups
configure_backup() {
    log "Configuration des backups..."
    mkdir -p /backup/n8n
    
    cat > /usr/local/bin/n8n-backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/n8n"
DATE=$(date +%Y%m%d_%H%M%S)
sudo -u postgres pg_dump n8n | gzip > $BACKUP_DIR/n8n_db_$DATE.sql.gz
tar -czf $BACKUP_DIR/n8n_data_$DATE.tar.gz /home/n8n/.n8n/
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete
EOF
    
    chmod +x /usr/local/bin/n8n-backup.sh
    echo "0 2 * * * /usr/local/bin/n8n-backup.sh" | crontab -
}

# Sauvegarde des credentials
save_credentials() {
    cat > /root/n8n-credentials.txt <<EOF
===========================================
n8n KeyBuzz - Informations de connexion
===========================================
Date d'installation : $(date)
Domaine : https://$DOMAIN_NAME
IP directe : http://$PUBLIC_IP:8080

MOTS DE PASSE (À SAUVEGARDER !) :
-----------------------------------------
DB Password : $DB_PASSWORD
Encryption Key : $N8N_ENCRYPTION_KEY
Redis Password : $REDIS_PASSWORD

COMMANDES UTILES :
-----------------------------------------
Status : sudo -u n8n pm2 status
Logs : sudo -u n8n pm2 logs
Restart : sudo -u n8n pm2 restart n8n

GitHub : https://github.com/KeyBuzz/n8n
===========================================
EOF
    
    chmod 600 /root/n8n-credentials.txt
}

# Affichage final
show_summary() {
    clear
    print_logo
    echo -e "${GREEN}✅ Installation terminée avec succès !${NC}"
    echo ""
    echo -e "${YELLOW}📋 INFORMATIONS IMPORTANTES :${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "URL : ${BLUE}https://$DOMAIN_NAME${NC}"
    echo -e "URL directe : ${BLUE}http://$PUBLIC_IP:8080${NC}"
    echo ""
    echo -e "${RED}⚠️  MOTS DE PASSE (notez-les maintenant !) :${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "DB Password : $DB_PASSWORD"
    echo "Encryption Key : $N8N_ENCRYPTION_KEY"
    echo "Redis Password : $REDIS_PASSWORD"
    echo ""
    echo -e "${GREEN}Ces informations sont aussi sauvées dans :${NC}"
    echo "/root/n8n-credentials.txt"
    echo ""
    echo -e "${BLUE}🚀 Prochaines étapes :${NC}"
    echo "1. Accédez à https://$DOMAIN_NAME"
    echo "2. Créez votre compte administrateur"
    echo "3. Configurez vos workflows"
    echo ""
    echo "GitHub : https://github.com/KeyBuzz/n8n"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Installation principale
main() {
    print_logo
    check_root
    check_ubuntu
    
    log "Démarrage de l'installation n8n pour KeyBuzz..."
    
    update_system
    configure_system
    install_nodejs
    install_postgresql
    install_redis
    install_n8n
    configure_nginx
    configure_firewall
    configure_ssl
    configure_backup
    save_credentials
    
    show_summary
}

# Lancer l'installation
main "$@"
