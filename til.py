#!/usr/bin/env python3
"""
Tor Isolation Layer (TIL) - For Multi-Tenant Hosting Platform
Native Isolation - for Clear + Darknet
"""
# ------------------------------------------------------------------
# COPYRIGHT & LICENSING
# ------------------------------------------------------------------
# Copyright (C) 2025 Volkan Sah (Kücükbudak)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# A copy of the GNU General Public License (GPLv3) must be included
# with this distribution.
#
# --- ATTENTION: MANDATORY GPLv3 REQUIREMENTS ---
#
# 1. YOU MUST RETAIN THIS COPYRIGHT NOTICE: This code is FREE, but it is 
#    NOT Public Domain. Volkan Sah (Kücükbudak) holds the copyright. 
#    Removing this copyright line is a direct violation of the GPLv3 
#    and immediately terminates your right to use the code. 
#
# 2. YOU MUST SHARE YOUR CHANGES: If you modify this code and distribute it, 
#    your modified version MUST ALSO be released under the GPLv3, 
#    and you MUST provide the source code.
#
# Respect the work of developers who provide secure, open code. Do not remove 
# or obscure the author's identity.
# ------------------------------------------------------------------
# translated in english with ai was to lazy ;) Icions as a feature
# ------------------------------------------------------------------
#!/usr/bin/env python3
import subprocess
import json
import pwd
import grp
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import secrets


@dataclass
class NetworkPolicy:
    """Network Isolation Policy for a Tenant"""
    # Isolation Level (choose ONE)
    STRICT_ISOLATION = "strict"      # Own services only, no internet
    CLEARNET_API = "clearnet_api"    # + HTTPS to external APIs
    CLEARNET_FULL = "clearnet_full"  # + HTTP/HTTPS to any destination
    TOR_ONLY = "tor_only"            # Only via local Tor SOCKS proxy
    
    policy_type: str = STRICT_ISOLATION
    
    # Advanced Options
    allow_dns: bool = False          # Allow DNS lookups
    allow_ntp: bool = False          # NTP time queries
    allowed_domains: List[str] = None  # Whitelist for Clearnet domains
    tor_socks_port: int = 0          # If TOR_ONLY: local SOCKS port


@dataclass
class TenantConfig:
    """Configuration for a Tenant (Customer)"""
    tenant_id: str
    clearnet_domain: Optional[str]  # e.g., customer1.example.com (optional)
    apache_port: int                # Port for Hidden Service
    php_fpm_port: int                # Dedicated PHP-FPM Port
    mysql_port: int                  # Dedicated MySQL Port (3306 + offset)
    pgsql_port: int                  # Dedicated PostgreSQL Port (5432 + offset)
    unix_user: str                   # e.g., tenant_customer1
    web_root: Path                   # /var/www/tenants/customer1
    network_policy: NetworkPolicy = None  # Network Isolation Policy
    
    def __post_init__(self):
        # Default: Strict Isolation
        if self.network_policy is None:
            self.network_policy = NetworkPolicy()


class MultiTenantHostingManager:
    """Manages Multi-Tenant CMS Hosting with strict Isolation"""
    
    BASE_WEB_DIR = Path("/var/www/tenants")
    BASE_DB_DIR = Path("/var/lib/mysql-tenants")
    BASE_PGSQL_DIR = Path("/var/lib/postgresql-tenants")
    PHP_FPM_POOL_DIR = Path("/etc/php/8.2/fpm/pool.d")  # Adjust to your PHP version
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
    
    def _run_cmd(self, cmd: List[str], description: str = "") -> bool:
        """Executes command with error handling"""
        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(cmd)}")
            if description:
                print(f"         └─ {description}")
            return True
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            if description:
                print(f"✅ {description}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Error: {description}")
            print(f"   Command: {' '.join(cmd)}")
            print(f"   Error: {e.stderr}")
            return False
    
    def create_tenant(self, config: TenantConfig):
        """Creates complete Tenant with all services"""
        print(f"\n🚀 Creating Tenant: {config.tenant_id}")
        print("=" * 70)
        
        # 1. Create Unix User
        self._create_unix_user(config)
        
        # 2. Create Directories
        self._create_directories(config)
        
        # 3. Configure PHP-FPM Pool
        self._create_php_fpm_pool(config)
        
        # 4. Create MySQL Instance
        self._create_mysql_instance(config)
        
        # 5. Create PostgreSQL Instance (optional)
        self._create_pgsql_instance(config)
        
        # 6. Create Apache VirtualHost
        self._create_apache_vhost(config)
        
        # 7. Configure Tor Hidden Service
        self._create_tor_service(config)
        
        # 8. Set Firewall Rules
        self._apply_firewall_rules(config)
        
        print(f"\n✅ Tenant {config.tenant_id} successfully created!")
        self._print_tenant_info(config)
    
    def _create_unix_user(self, config: TenantConfig):
        """Creates dedicated Unix user per Tenant"""
        print(f"\n👤 Creating Unix User: {config.unix_user}")
        
        # Create user (no login, no home)
        self._run_cmd([
            "sudo", "useradd",
            "--system",
            "--no-create-home",
            "--shell", "/usr/sbin/nologin",
            config.unix_user
        ], f"User {config.unix_user} created")
        
        # Add to www-data group (for Apache access)
        self._run_cmd([
            "sudo", "usermod", "-a", "-G", "www-data", config.unix_user
        ], f"User added to www-data group")
    
    def _create_directories(self, config: TenantConfig):
        """Creates all necessary directories"""
        print(f"\n📁 Creating Directories for {config.tenant_id}")
        
        dirs = [
            config.web_root,
            config.web_root / "public_html",
            config.web_root / "logs",
            config.web_root / "tmp",
            config.web_root / "sessions",
            self.BASE_DB_DIR / config.tenant_id,
            self.BASE_PGSQL_DIR / config.tenant_id,
        ]
        
        for directory in dirs:
            directory.mkdir(parents=True, exist_ok=True)
            self._run_cmd([
                "sudo", "chown", "-R",
                f"{config.unix_user}:www-data",
                str(directory)
            ], f"Owner set: {directory}")
            
            self._run_cmd([
                "sudo", "chmod", "750", str(directory)
            ], f"Permissions set: {directory}")
    
    def _create_php_fpm_pool(self, config: TenantConfig):
        """Creates dedicated PHP-FPM Pool"""
        print(f"\n🐘 Creating PHP-FPM Pool for {config.tenant_id}")
        
        pool_config = f"""[{config.tenant_id}]
user = {config.unix_user}
group = www-data

listen = 127.0.0.1:{config.php_fpm_port}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500

; Isolation
php_admin_value[open_basedir] = {config.web_root}:/tmp
php_admin_value[upload_tmp_dir] = {config.web_root}/tmp
php_admin_value[session.save_path] = {config.web_root}/sessions
php_admin_value[sys_temp_dir] = {config.web_root}/tmp

; Security
php_admin_flag[allow_url_fopen] = off
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; Logging
php_admin_value[error_log] = {config.web_root}/logs/php-error.log
php_admin_flag[log_errors] = on

; Memory & Performance
php_admin_value[memory_limit] = 128M
php_admin_value[max_execution_time] = 30
php_admin_value[max_input_time] = 30
php_admin_value[post_max_size] = 10M
php_admin_value[upload_max_filesize] = 10M
"""
        
        pool_file = self.PHP_FPM_POOL_DIR / f"{config.tenant_id}.conf"
        
        if not self.dry_run:
            pool_file.write_text(pool_config)
            print(f"✅ PHP-FPM Pool configured: {pool_file}")
        else:
            print(f"[DRY-RUN] Would write Pool Config: {pool_file}")
        
        # Reload PHP-FPM
        self._run_cmd([
            "sudo", "systemctl", "reload", "php8.2-fpm"
        ], "PHP-FPM reloaded")
    
    def _create_mysql_instance(self, config: TenantConfig):
        """Creates dedicated MySQL instance with its own socket"""
        print(f"\n🗄️ Creating MySQL Instance for {config.tenant_id}")
        
        data_dir = self.BASE_DB_DIR / config.tenant_id / "data"
        socket_file = self.BASE_DB_DIR / config.tenant_id / f"mysql-{config.tenant_id}.sock"
        
        # Initialize MySQL Data Directory
        self._run_cmd([
            "sudo", "mysql_install_db",
            f"--datadir={data_dir}",
            f"--user={config.unix_user}"
        ], f"MySQL Data Directory initialized: {data_dir}")
        
        # MySQL Config for this instance
        mysql_config = f"""[mysqld]
datadir = {data_dir}
socket = {socket_file}
port = {config.mysql_port}
bind-address = 127.0.0.1

user = {config.unix_user}
pid-file = {self.BASE_DB_DIR}/{config.tenant_id}/mysql.pid

# Isolation & Security
skip-networking = 0
local-infile = 0
symbolic-links = 0

# Performance (adjust as needed)
max_connections = 50
innodb_buffer_pool_size = 128M

# Logging
log_error = {config.web_root}/logs/mysql-error.log
"""
        
        mysql_conf_file = self.BASE_DB_DIR / config.tenant_id / "my.cnf"
        
        if not self.dry_run:
            mysql_conf_file.write_text(mysql_config)
            print(f"✅ MySQL Config created: {mysql_conf_file}")
        
        # Create Systemd Service
        self._create_mysql_systemd_service(config, mysql_conf_file)
        
        # Generate random Root Password
        root_password = secrets.token_urlsafe(32)
        password_file = self.BASE_DB_DIR / config.tenant_id / "mysql_root_password.txt"
        
        if not self.dry_run:
            password_file.write_text(root_password)
            password_file.chmod(0o600)
            print(f"✅ MySQL Root Password stored: {password_file}")
    
    def _create_mysql_systemd_service(self, config: TenantConfig, conf_file: Path):
        """Creates Systemd Service for MySQL instance"""
        service_content = f"""[Unit]
Description=MySQL Server for Tenant {config.tenant_id}
After=network.target

[Service]
Type=notify
User={config.unix_user}
Group=www-data

ExecStart=/usr/sbin/mysqld --defaults-file={conf_file}
Restart=on-failure
RestartSec=5

# Isolation
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths={self.BASE_DB_DIR}/{config.tenant_id}
ReadWritePaths={config.web_root}/logs

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path(f"/etc/systemd/system/mysql-{config.tenant_id}.service")
        
        if not self.dry_run:
            service_file.write_text(service_content)
            
        self._run_cmd([
            "sudo", "systemctl", "daemon-reload"
        ], "Systemd reloaded")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"mysql-{config.tenant_id}"
        ], f"MySQL Service enabled: mysql-{config.tenant_id}")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"mysql-{config.tenant_id}"
        ], f"MySQL Service started")
    
    def _create_pgsql_instance(self, config: TenantConfig):
        """Creates dedicated PostgreSQL instance"""
        print(f"\n🐘 Creating PostgreSQL Instance for {config.tenant_id}")
        
        data_dir = self.BASE_PGSQL_DIR / config.tenant_id / "data"
        socket_dir = self.BASE_PGSQL_DIR / config.tenant_id / "sockets"
        
        # Create directories
        data_dir.mkdir(parents=True, exist_ok=True)
        socket_dir.mkdir(parents=True, exist_ok=True)
        
        # Set owner (PostgreSQL runs as config.unix_user)
        self._run_cmd([
            "sudo", "chown", "-R",
            f"{config.unix_user}:www-data",
            str(self.BASE_PGSQL_DIR / config.tenant_id)
        ], "PostgreSQL Directories: Owner set")
        
        # Initialize PostgreSQL Data Directory
        self._run_cmd([
            "sudo", "-u", config.unix_user,
            "/usr/lib/postgresql/15/bin/initdb",  # Adjust to your PostgreSQL version
            "-D", str(data_dir),
            "--encoding=UTF8",
            "--locale=C",
            "--auth=scram-sha-256"
        ], f"PostgreSQL Data Directory initialized: {data_dir}")
        
        # Adjust postgresql.conf
        pg_config = f"""# PostgreSQL Configuration for Tenant {config.tenant_id}
# Auto-generated - Do not edit manually

# Connection Settings
listen_addresses = '127.0.0.1'
port = {config.pgsql_port}
max_connections = 50
unix_socket_directories = '{socket_dir}'

# Memory Settings
shared_buffers = 128MB
effective_cache_size = 512MB
work_mem = 4MB
maintenance_work_mem = 64MB

# Write Ahead Log
wal_level = minimal
max_wal_senders = 0
checkpoint_timeout = 15min

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = '{config.web_root}/logs'
log_filename = 'postgresql-%Y-%m-%d.log'
log_line_prefix = '%m [%p] %u@%d '
log_timezone = 'UTC'

# Locale
datestyle = 'iso, mdy'
timezone = 'UTC'
lc_messages = 'C'
lc_monetary = 'C'
lc_numeric = 'C'
lc_time = 'C'

# Security
ssl = off
password_encryption = scram-sha-256

# Performance (adjust as needed)
random_page_cost = 1.1
effective_io_concurrency = 200
"""
        
        pg_conf_file = data_dir / "postgresql.conf"
        
        if not self.dry_run:
            pg_conf_file.write_text(pg_config)
            print(f"✅ PostgreSQL Config created: {pg_conf_file}")
        
        # pg_hba.conf for local connections
        pg_hba = f"""# PostgreSQL Host-Based Authentication for Tenant {config.tenant_id}
# TYPE  DATABASE        USER            ADDRESS                         METHOD

# Local connections via Unix socket
local   all             all                                             scram-sha-256

# Local connections via TCP/IP (127.0.0.1 only)
host    all             all             127.0.0.1/32                    scram-sha-256
host    all             all             ::1/128                         scram-sha-256
"""
        
        pg_hba_file = data_dir / "pg_hba.conf"
        
        if not self.dry_run:
            pg_hba_file.write_text(pg_hba)
            print(f"✅ PostgreSQL HBA Config created: {pg_hba_file}")
        
        # Create Systemd Service
        self._create_pgsql_systemd_service(config, data_dir)
        
        # Random password for postgres user
        postgres_password = secrets.token_urlsafe(32)
        password_file = self.BASE_PGSQL_DIR / config.tenant_id / "postgres_password.txt"
        
        if not self.dry_run:
            password_file.write_text(postgres_password)
            password_file.chmod(0o600)
            print(f"✅ PostgreSQL Password stored: {password_file}")
            
            # Note: Password must be set after startup
            print(f"⚠️ Must be executed manually after startup:")
            print(f"   sudo -u {config.unix_user} psql -p {config.pgsql_port} -c \"ALTER USER postgres PASSWORD '{postgres_password}';\"")
    
    def _create_pgsql_systemd_service(self, config: TenantConfig, data_dir: Path):
        """Creates Systemd Service for PostgreSQL instance"""
        service_content = f"""[Unit]
Description=PostgreSQL Server for Tenant {config.tenant_id}
After=network.target

[Service]
Type=notify
User={config.unix_user}
Group=www-data

# PostgreSQL Binary (adjust to your version)
ExecStart=/usr/lib/postgresql/15/bin/postgres -D {data_dir}
ExecReload=/bin/kill -HUP $MAINPID

# Restart on failure
Restart=on-failure
RestartSec=5
TimeoutSec=120

# Security Hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths={self.BASE_PGSQL_DIR}/{config.tenant_id}
ReadWritePaths={config.web_root}/logs

# Environment
Environment=PGDATA={data_dir}

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path(f"/etc/systemd/system/postgresql-{config.tenant_id}.service")
        
        if not self.dry_run:
            service_file.write_text(service_content)
            
        self._run_cmd([
            "sudo", "systemctl", "daemon-reload"
        ], "Systemd reloaded")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"postgresql-{config.tenant_id}"
        ], f"PostgreSQL Service enabled: postgresql-{config.tenant_id}")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"postgresql-{config.tenant_id}"
        ], f"PostgreSQL Service started")
    
    def _create_apache_vhost(self, config: TenantConfig):
        """Creates Apache VirtualHost (for Hidden Service & optional Clearnet)"""
        print(f"\n🌐 Creating Apache VirtualHost for {config.tenant_id}")
        
        # Hidden Service VirtualHost
        vhost_hs = f"""<VirtualHost *:{config.apache_port}>
    ServerName {config.tenant_id}.onion
    DocumentRoot {config.web_root}/public_html
    
    # PHP-FPM via TCP
    <FilesMatch \\.php$>
        SetHandler "proxy:fcgi://127.0.0.1:{config.php_fpm_port}"
    </FilesMatch>
    
    <Directory {config.web_root}/public_html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Logging
    ErrorLog {config.web_root}/logs/apache-error.log
    CustomLog {config.web_root}/logs/apache-access.log combined
    
    # Security
    ServerSignature Off
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>
"""
        
        vhost_file = Path(f"/etc/apache2/sites-available/{config.tenant_id}-hs.conf")
        
        if not self.dry_run:
            vhost_file.write_text(vhost_hs)
        
        self._run_cmd([
            "sudo", "a2ensite", f"{config.tenant_id}-hs.conf"
        ], f"VirtualHost enabled: {config.tenant_id}-hs")
        
        # Optional: Clearnet VirtualHost
        if config.clearnet_domain:
            vhost_clearnet = vhost_hs.replace(
                f"*:{config.apache_port}",
                "*:443"
            ).replace(
                f"{config.tenant_id}.onion",
                config.clearnet_domain
            ) + """
    # SSL (certbot handles this)
    # SSLEngine on
    # SSLCertificateFile ...
    # SSLCertificateKeyFile ...
"""
            clearnet_file = Path(f"/etc/apache2/sites-available/{config.tenant_id}-clearnet.conf")
            if not self.dry_run:
                clearnet_file.write_text(vhost_clearnet)
            
            print(f"✅ Clearnet VirtualHost created (add SSL via certbot manually)")
        
        # Reload Apache
        self._run_cmd([
            "sudo", "systemctl", "reload", "apache2"
        ], "Apache reloaded")
    
    def _create_tor_service(self, config: TenantConfig):
        """Creates Tor Hidden Service (as in your original)"""
        print(f"\n🧅 Creating Tor Hidden Service for {config.tenant_id}")
        
        tor_dir = Path(f"/etc/tor/instances/{config.tenant_id}")
        tor_data_dir = Path(f"/var/lib/tor/instances/{config.tenant_id}")
        
        tor_dir.mkdir(parents=True, exist_ok=True)
        tor_data_dir.mkdir(parents=True, exist_ok=True)
        (tor_data_dir / "hidden_service").mkdir(exist_ok=True)
        
        torrc = f"""RunAsDaemon 0
DataDirectory {tor_data_dir}
PidFile /run/tor/instances/{config.tenant_id}/{config.tenant_id}.pid

SocksPort 0
ExitRelay 0
ControlPort 0

HiddenServiceDir {tor_data_dir}/hidden_service/
HiddenServicePort 80 127.0.0.1:{config.apache_port}

Log notice syslog
"""
        
        torrc_file = tor_dir / "torrc"
        if not self.dry_run:
            torrc_file.write_text(torrc)
        
        # Permissions
        self._run_cmd([
            "sudo", "chown", "-R", "debian-tor:debian-tor",
            str(tor_dir), str(tor_data_dir)
        ], "Tor Directories: Owner set")
        
        self._run_cmd([
            "sudo", "chmod", "700", str(tor_data_dir / "hidden_service")
        ], "Hidden Service Dir: Permissions set")
        
        # Systemd Service (like your template)
        service_content = f"""[Unit]
Description=Tor Hidden Service {config.tenant_id}
After=network.target

[Service]
User=debian-tor
Type=simple
ExecStart=/usr/sbin/tor -f {torrc_file}
Restart=on-failure
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={tor_data_dir} /run/tor/instances/{config.tenant_id}
RuntimeDirectory=tor/instances/{config.tenant_id}
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path(f"/etc/systemd/system/tor@{config.tenant_id}.service")
        if not self.dry_run:
            service_file.write_text(service_content)
        
        self._run_cmd([
            "sudo", "systemctl", "daemon-reload"
        ], "Systemd reloaded")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"tor@{config.tenant_id}"
        ], f"Tor Service enabled")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"tor@{config.tenant_id}"
        ], f"Tor Service started")
    
    def _apply_firewall_rules(self, config: TenantConfig):
        """
        Sets strict iptables rules based on Network Policy
        Supports various isolation levels
        """
        print(f"\n🔥 Setting Firewall Rules for {config.tenant_id}")
        print(f"   Policy: {config.network_policy.policy_type}")
        
        uid = self._get_user_uid(config.unix_user)
        if uid is None:
            print(f"⚠️ User {config.unix_user} not found - Firewall setup skipped")
            return
        
        policy = config.network_policy
        rules = []
        
        # === PHASE 1: ESTABLISHED/RELATED (always allowed) ===
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-m conntrack --ctstate ESTABLISHED,RELATED "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Established' "
            f"-j ACCEPT"
        ))
        
        # === PHASE 2: WHITELIST - Own Services ===
        
        # MySQL
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport {config.mysql_port} "
            f"-m comment --comment 'Tenant_{config.tenant_id}_MySQL' "
            f"-j ACCEPT"
        ))
        
        # PostgreSQL
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport {config.pgsql_port} "
            f"-m comment --comment 'Tenant_{config.tenant_id}_PostgreSQL' "
            f"-j ACCEPT"
        ))
        
        # === PHASE 3: POLICY-DEPENDENT RULES ===
        
        if policy.policy_type == NetworkPolicy.STRICT_ISOLATION:
            # Option A: STRICT ISOLATION - No Internet
            print(f"   🔒 Strict Isolation: Only internal services allowed")
            
            # DNS and NTP are explicitly NOT allowed
            # Jump directly to BLACKLIST
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_API:
            # Option B: Clearnet API Access
            print(f"   🌐 Clearnet API Access: DNS + HTTPS allowed")
            
            # Allow DNS
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp --dport 53 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_DNS' "
                f"-j ACCEPT"
            ))
            
            # Allow HTTPS (443) - Standard for APIs
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p tcp --dport 443 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_HTTPS' "
                f"-j ACCEPT"
            ))
            
            # IMPORTANT: HTTP (80) is NOT allowed in CLEARNET_API
            # Reason: APIs should only communicate over encrypted connections
            # If HTTP is truly necessary, use CLEARNET_FULL
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_FULL:
            # Option C: Full Clearnet Access (like a regular web server)
            print(f"   🌍 Full Clearnet Access: DNS + HTTP/HTTPS allowed")
            
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp --dport 53 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_DNS' "
                f"-j ACCEPT"
            ))
            
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p tcp -m multiport --dports 80,443 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_HTTP_HTTPS' "
                f"-j ACCEPT"
            ))
            
        elif policy.policy_type == NetworkPolicy.TOR_ONLY:
            # Option D: Only via local Tor SOCKS proxy
            print(f"   🧅 Tor-Only: Only SOCKS proxy on Port {policy.tor_socks_port}")
            
            if policy.tor_socks_port > 0:
                rules.append((
                    f"-A OUTPUT -m owner --uid-owner {uid} "
                    f"-d 127.0.0.1 -p tcp --dport {policy.tor_socks_port} "
                    f"-m comment --comment 'Tenant_{config.tenant_id}_TOR_SOCKS' "
                    f"-j ACCEPT"
                ))
            else:
                print(f"   ⚠️ Tor SOCKS port not configured!")
        
        # === PHASE 4: BLACKLIST - Explicit blocks (Defense in Depth) ===
        
        # Block all MySQL ports (except own - already allowed)
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 3306:3400 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_MySQL_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # Block all PostgreSQL ports (except own)
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 5432:5532 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_PostgreSQL_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # Block all PHP-FPM Ports
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 9000:9200 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_PHP_FPM_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # === PHASE 5: DEFAULT DENY - Block everything else ===
        
        # TCP Default Deny
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-p tcp "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_TCP' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # UDP Default Deny (with exception for DNS if allowed)
        if policy.allow_dns or policy.policy_type in [NetworkPolicy.CLEARNET_API, NetworkPolicy.CLEARNET_FULL]:
            # DNS was already allowed, block the rest
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp ! --dport 53 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_UDP' "
                f"-j REJECT --reject-with icmp-port-unreachable"
            ))
        else:
            # No DNS allowed, block all UDP
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp "
                f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_UDP_All' "
                f"-j REJECT --reject-with icmp-port-unreachable"
            ))
        
        # === APPLY RULES ===
        
        print(f"\n   Applying {len(rules)} Firewall Rules...")
        for i, rule in enumerate(rules, 1):
            comment = rule.split("--comment")[1].split("'")[1] if "--comment" in rule else f"Rule_{i}"
            self._run_cmd(
                ["sudo", "iptables"] + rule.split(),
                f"   [{i:2d}/{len(rules)}] {comment}"
            )
        
        print(f"\n✅ Firewall rules for {config.tenant_id} successfully set")
        self._print_policy_summary(config)
    
    def _print_policy_summary(self, config: TenantConfig):
        """Displays summary of the Network Policy"""
        policy = config.network_policy
        
        print("\n" + "─" * 70)
        print(f"📋 Network Policy for {config.tenant_id}")
        print("─" * 70)
        print(f"Policy Type: {policy.policy_type}")
        print("\n✅ Allowed Connections:")
        print(f"   • 127.0.0.1:{config.mysql_port} (MySQL)")
        print(f"   • 127.0.0.1:{config.pgsql_port} (PostgreSQL)")
        
        if policy.policy_type == NetworkPolicy.STRICT_ISOLATION:
            print("\n❌ Blocked:")
            print(f"   • All external connections (no Internet)")
            print(f"   • DNS Lookups")
            print(f"   • Other Tenant Services")
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_API:
            print(f"   • *:53 (DNS)")
            print(f"   • *:443 (HTTPS)")
            print("\n❌ Blocked:")
            print(f"   • HTTP Port 80 (only HTTPS allowed)")
            print(f"   • Other Tenant Services")
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_FULL:
            print(f"   • *:53 (DNS)")
            print(f"   • *:80,443 (HTTP/HTTPS)")
            print("\n❌ Blocked:")
            print(f"   • Other Tenant Services")
            
        elif policy.policy_type == NetworkPolicy.TOR_ONLY:
            print(f"   • 127.0.0.1:{policy.tor_socks_port} (Tor SOCKS)")
            print("\n❌ Blocked:")
            print(f"   • Direct Internet Connections")
            print(f"   • DNS (Tor handles DNS)")
            print(f"   • Other Tenant Services")
        
        print("─" * 70 + "\n")
    
    def _get_user_uid(self, username: str) -> Optional[int]:
        """Gets the UID of a Unix user"""
        try:
            return pwd.getpwnam(username).pw_uid
        except KeyError:
            return None
    
    def _print_tenant_info(self, config: TenantConfig):
        """Outputs important Tenant information"""
        hostname_file = Path(f"/var/lib/tor/instances/{config.tenant_id}/hidden_service/hostname")
        
        onion_address = "Not yet generated - wait 30 seconds"
        if not self.dry_run and hostname_file.exists():
            onion_address = hostname_file.read_text().strip()
        
        print("\n" + "=" * 70)
        print(f"📋 Tenant Information: {config.tenant_id}")
        print("=" * 70)
        print(f"🧅 Onion Address:     {onion_address}")
        print(f"🌐 Clearnet Domain:   {config.clearnet_domain or 'N/A'}")
        print(f"👤 Unix User:         {config.unix_user}")
        print(f"📂 Web Root:          {config.web_root}")
        print(f"🐘 PHP-FPM Port:      {config.php_fpm_port}")
        print(f"🗄️ MySQL Port:        {config.mysql_port}")
        print(f"🐘 PostgreSQL Port:   {config.pgsql_port}")
        print(f"🔥 Network Policy:    {config.network_policy.policy_type}")
        print("=" * 70)
