#!/usr/bin/env python3
"""
Tor Isolation Layer (TIL) - For Multi-Tenant Hosting Platform
Native Isolation - for Clear + Darknet
"""
# ------------------------------------------------------------------
# COPYRIGHT & LICENSING
# ------------------------------------------------------------------
# Copyright (C) 2024 Volkan Sah (Kücükbudak)
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
    """Netzwerk-Isolation-Policy für einen Tenant"""
    # Isolation-Level (wähle EINEN)
    STRICT_ISOLATION = "strict"      # Nur eigene Services, kein Internet
    CLEARNET_API = "clearnet_api"    # + HTTPS zu externen APIs
    CLEARNET_FULL = "clearnet_full"  # + HTTP/HTTPS zu beliebigen Zielen
    TOR_ONLY = "tor_only"            # Nur über lokalen Tor-SOCKS-Proxy
    
    policy_type: str = STRICT_ISOLATION
    
    # Erweiterte Optionen
    allow_dns: bool = False          # DNS-Lookups erlauben
    allow_ntp: bool = False          # NTP-Zeitabfragen
    allowed_domains: List[str] = None  # Whitelist für Clearnet-Domains
    tor_socks_port: int = 0          # Falls TOR_ONLY: lokaler SOCKS-Port


@dataclass
class TenantConfig:
    """Konfiguration für einen Mandanten (Kunde)"""
    tenant_id: str
    clearnet_domain: Optional[str]  # z.B. kunde1.beispiel.de (optional)
    apache_port: int                 # Port für Hidden Service
    php_fpm_port: int                # Dedizierter PHP-FPM Port
    mysql_port: int                  # Dedizierter MySQL Port (3306 + offset)
    pgsql_port: int                  # Dedizierter PostgreSQL Port (5432 + offset)
    unix_user: str                   # z.B. tenant_kunde1
    web_root: Path                   # /var/www/tenants/kunde1
    network_policy: NetworkPolicy = None  # Netzwerk-Isolation-Policy
    
    def __post_init__(self):
        # Default: Strikte Isolation
        if self.network_policy is None:
            self.network_policy = NetworkPolicy()


class MultiTenantHostingManager:
    """Verwaltet Multi-Tenant CMS-Hosting mit strikter Isolation"""
    
    BASE_WEB_DIR = Path("/var/www/tenants")
    BASE_DB_DIR = Path("/var/lib/mysql-tenants")
    BASE_PGSQL_DIR = Path("/var/lib/postgresql-tenants")
    PHP_FPM_POOL_DIR = Path("/etc/php/8.2/fpm/pool.d")  # Anpassen an deine PHP-Version
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
    
    def _run_cmd(self, cmd: List[str], description: str = "") -> bool:
        """Führt Befehl aus mit Error-Handling"""
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
            print(f"❌ Fehler: {description}")
            print(f"   Befehl: {' '.join(cmd)}")
            print(f"   Fehler: {e.stderr}")
            return False
    
    def create_tenant(self, config: TenantConfig):
        """Erstellt kompletten Tenant mit allen Services"""
        print(f"\n🚀 Erstelle Tenant: {config.tenant_id}")
        print("=" * 70)
        
        # 1. Unix-User erstellen
        self._create_unix_user(config)
        
        # 2. Verzeichnisse anlegen
        self._create_directories(config)
        
        # 3. PHP-FPM Pool konfigurieren
        self._create_php_fpm_pool(config)
        
        # 4. MySQL-Instanz erstellen
        self._create_mysql_instance(config)
        
        # 5. PostgreSQL-Instanz erstellen (optional)
        self._create_pgsql_instance(config)
        
        # 6. Apache VirtualHost erstellen
        self._create_apache_vhost(config)
        
        # 7. Tor Hidden Service konfigurieren
        self._create_tor_service(config)
        
        # 8. Firewall-Regeln setzen
        self._apply_firewall_rules(config)
        
        print(f"\n✅ Tenant {config.tenant_id} erfolgreich erstellt!")
        self._print_tenant_info(config)
    
    def _create_unix_user(self, config: TenantConfig):
        """Erstellt dedizierten Unix-User pro Tenant"""
        print(f"\n👤 Erstelle Unix-User: {config.unix_user}")
        
        # User erstellen (kein Login, kein Home)
        self._run_cmd([
            "sudo", "useradd",
            "--system",
            "--no-create-home",
            "--shell", "/usr/sbin/nologin",
            config.unix_user
        ], f"User {config.unix_user} erstellt")
        
        # Zur www-data Gruppe hinzufügen (für Apache-Zugriff)
        self._run_cmd([
            "sudo", "usermod", "-a", "-G", "www-data", config.unix_user
        ], f"User zu www-data Gruppe hinzugefügt")
    
    def _create_directories(self, config: TenantConfig):
        """Erstellt alle nötigen Verzeichnisse"""
        print(f"\n📁 Erstelle Verzeichnisse für {config.tenant_id}")
        
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
            ], f"Besitzer gesetzt: {directory}")
            
            self._run_cmd([
                "sudo", "chmod", "750", str(directory)
            ], f"Rechte gesetzt: {directory}")
    
    def _create_php_fpm_pool(self, config: TenantConfig):
        """Erstellt dedizierten PHP-FPM Pool"""
        print(f"\n🐘 Erstelle PHP-FPM Pool für {config.tenant_id}")
        
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

; Sicherheit
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
            print(f"✅ PHP-FPM Pool konfiguriert: {pool_file}")
        else:
            print(f"[DRY-RUN] Würde Pool-Config schreiben: {pool_file}")
        
        # PHP-FPM neu laden
        self._run_cmd([
            "sudo", "systemctl", "reload", "php8.2-fpm"
        ], "PHP-FPM neu geladen")
    
    def _create_mysql_instance(self, config: TenantConfig):
        """Erstellt dedizierte MySQL-Instanz mit eigenem Socket"""
        print(f"\n🗄️  Erstelle MySQL-Instanz für {config.tenant_id}")
        
        data_dir = self.BASE_DB_DIR / config.tenant_id / "data"
        socket_file = self.BASE_DB_DIR / config.tenant_id / f"mysql-{config.tenant_id}.sock"
        
        # MySQL Data Directory initialisieren
        self._run_cmd([
            "sudo", "mysql_install_db",
            f"--datadir={data_dir}",
            f"--user={config.unix_user}"
        ], f"MySQL Data Directory initialisiert: {data_dir}")
        
        # MySQL Config für diese Instanz
        mysql_config = f"""[mysqld]
datadir = {data_dir}
socket = {socket_file}
port = {config.mysql_port}
bind-address = 127.0.0.1

user = {config.unix_user}
pid-file = {self.BASE_DB_DIR}/{config.tenant_id}/mysql.pid

# Isolation & Sicherheit
skip-networking = 0
local-infile = 0
symbolic-links = 0

# Performance (anpassen je nach Bedarf)
max_connections = 50
innodb_buffer_pool_size = 128M

# Logging
log_error = {config.web_root}/logs/mysql-error.log
"""
        
        mysql_conf_file = self.BASE_DB_DIR / config.tenant_id / "my.cnf"
        
        if not self.dry_run:
            mysql_conf_file.write_text(mysql_config)
            print(f"✅ MySQL Config erstellt: {mysql_conf_file}")
        
        # Systemd Service erstellen
        self._create_mysql_systemd_service(config, mysql_conf_file)
        
        # Zufälliges Root-Passwort generieren
        root_password = secrets.token_urlsafe(32)
        password_file = self.BASE_DB_DIR / config.tenant_id / "mysql_root_password.txt"
        
        if not self.dry_run:
            password_file.write_text(root_password)
            password_file.chmod(0o600)
            print(f"✅ MySQL Root-Passwort: {password_file}")
    
    def _create_mysql_systemd_service(self, config: TenantConfig, conf_file: Path):
        """Erstellt Systemd-Service für MySQL-Instanz"""
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
        ], "Systemd neu geladen")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"mysql-{config.tenant_id}"
        ], f"MySQL-Service aktiviert: mysql-{config.tenant_id}")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"mysql-{config.tenant_id}"
        ], f"MySQL-Service gestartet")
    
    def _create_pgsql_instance(self, config: TenantConfig):
        """Erstellt dedizierte PostgreSQL-Instanz"""
        print(f"\n🐘 Erstelle PostgreSQL-Instanz für {config.tenant_id}")
        
        data_dir = self.BASE_PGSQL_DIR / config.tenant_id / "data"
        socket_dir = self.BASE_PGSQL_DIR / config.tenant_id / "sockets"
        
        # Verzeichnisse erstellen
        data_dir.mkdir(parents=True, exist_ok=True)
        socket_dir.mkdir(parents=True, exist_ok=True)
        
        # Besitzer setzen (PostgreSQL läuft als config.unix_user)
        self._run_cmd([
            "sudo", "chown", "-R",
            f"{config.unix_user}:www-data",
            str(self.BASE_PGSQL_DIR / config.tenant_id)
        ], "PostgreSQL-Verzeichnisse: Besitzer gesetzt")
        
        # PostgreSQL Data Directory initialisieren
        self._run_cmd([
            "sudo", "-u", config.unix_user,
            "/usr/lib/postgresql/15/bin/initdb",  # Anpassen an deine PostgreSQL-Version
            "-D", str(data_dir),
            "--encoding=UTF8",
            "--locale=C",
            "--auth=scram-sha-256"
        ], f"PostgreSQL Data Directory initialisiert: {data_dir}")
        
        # postgresql.conf anpassen
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

# Performance (anpassen je nach Bedarf)
random_page_cost = 1.1
effective_io_concurrency = 200
"""
        
        pg_conf_file = data_dir / "postgresql.conf"
        
        if not self.dry_run:
            pg_conf_file.write_text(pg_config)
            print(f"✅ PostgreSQL Config erstellt: {pg_conf_file}")
        
        # pg_hba.conf für lokale Verbindungen
        pg_hba = f"""# PostgreSQL Host-Based Authentication for Tenant {config.tenant_id}
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections via Unix socket
local   all             all                                     scram-sha-256

# Local connections via TCP/IP (127.0.0.1 only)
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
"""
        
        pg_hba_file = data_dir / "pg_hba.conf"
        
        if not self.dry_run:
            pg_hba_file.write_text(pg_hba)
            print(f"✅ PostgreSQL HBA Config erstellt: {pg_hba_file}")
        
        # Systemd Service erstellen
        self._create_pgsql_systemd_service(config, data_dir)
        
        # Zufälliges Passwort für postgres-User
        postgres_password = secrets.token_urlsafe(32)
        password_file = self.BASE_PGSQL_DIR / config.tenant_id / "postgres_password.txt"
        
        if not self.dry_run:
            password_file.write_text(postgres_password)
            password_file.chmod(0o600)
            print(f"✅ PostgreSQL Passwort: {password_file}")
            
            # Hinweis: Passwort muss nach dem Start gesetzt werden
            print(f"⚠️  Nach dem Start manuell ausführen:")
            print(f"   sudo -u {config.unix_user} psql -p {config.pgsql_port} -c \"ALTER USER postgres PASSWORD '{postgres_password}';\"")
    
    def _create_pgsql_systemd_service(self, config: TenantConfig, data_dir: Path):
        """Erstellt Systemd-Service für PostgreSQL-Instanz"""
        service_content = f"""[Unit]
Description=PostgreSQL Server for Tenant {config.tenant_id}
After=network.target

[Service]
Type=notify
User={config.unix_user}
Group=www-data

# PostgreSQL Binary (anpassen an deine Version)
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
        ], "Systemd neu geladen")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"postgresql-{config.tenant_id}"
        ], f"PostgreSQL-Service aktiviert: postgresql-{config.tenant_id}")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"postgresql-{config.tenant_id}"
        ], f"PostgreSQL-Service gestartet")
    
    def _create_apache_vhost(self, config: TenantConfig):
        """Erstellt Apache VirtualHost (für Hidden Service & optional Clearnet)"""
        print(f"\n🌐 Erstelle Apache VirtualHost für {config.tenant_id}")
        
        # Hidden Service VirtualHost
        vhost_hs = f"""<VirtualHost *:{config.apache_port}>
    ServerName {config.tenant_id}.onion
    DocumentRoot {config.web_root}/public_html
    
    # PHP-FPM über TCP
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
    
    # Sicherheit
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
        ], f"VirtualHost aktiviert: {config.tenant_id}-hs")
        
        # Optional: Clearnet VirtualHost
        if config.clearnet_domain:
            vhost_clearnet = vhost_hs.replace(
                f"*:{config.apache_port}",
                "*:443"
            ).replace(
                f"{config.tenant_id}.onion",
                config.clearnet_domain
            ) + """
    # SSL (certbot übernimmt das)
    # SSLEngine on
    # SSLCertificateFile ...
    # SSLCertificateKeyFile ...
"""
            clearnet_file = Path(f"/etc/apache2/sites-available/{config.tenant_id}-clearnet.conf")
            if not self.dry_run:
                clearnet_file.write_text(vhost_clearnet)
            
            print(f"✅ Clearnet VirtualHost erstellt (SSL via certbot manuell hinzufügen)")
        
        # Apache neu laden
        self._run_cmd([
            "sudo", "systemctl", "reload", "apache2"
        ], "Apache neu geladen")
    
    def _create_tor_service(self, config: TenantConfig):
        """Erstellt Tor Hidden Service (wie in deinem Original)"""
        print(f"\n🧅 Erstelle Tor Hidden Service für {config.tenant_id}")
        
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
        ], "Tor-Verzeichnisse: Besitzer gesetzt")
        
        self._run_cmd([
            "sudo", "chmod", "700", str(tor_data_dir / "hidden_service")
        ], "Hidden Service Dir: Rechte gesetzt")
        
        # Systemd-Service (wie dein Template)
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
        ], "Systemd neu geladen")
        
        self._run_cmd([
            "sudo", "systemctl", "enable", f"tor@{config.tenant_id}"
        ], f"Tor-Service aktiviert")
        
        self._run_cmd([
            "sudo", "systemctl", "start", f"tor@{config.tenant_id}"
        ], f"Tor-Service gestartet")
    
    def _apply_firewall_rules(self, config: TenantConfig):
        """
        Setzt strikte iptables-Regeln basierend auf Network Policy
        Unterstützt verschiedene Isolation-Level
        """
        print(f"\n🔥 Setze Firewall-Regeln für {config.tenant_id}")
        print(f"   Policy: {config.network_policy.policy_type}")
        
        uid = self._get_user_uid(config.unix_user)
        if uid is None:
            print(f"⚠️  User {config.unix_user} nicht gefunden - Firewall-Setup übersprungen")
            return
        
        policy = config.network_policy
        rules = []
        
        # === PHASE 1: ESTABLISHED/RELATED (immer erlaubt) ===
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-m conntrack --ctstate ESTABLISHED,RELATED "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Established' "
            f"-j ACCEPT"
        ))
        
        # === PHASE 2: WHITELIST - Eigene Services ===
        
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
        
        # === PHASE 3: POLICY-ABHÄNGIGE REGELN ===
        
        if policy.policy_type == NetworkPolicy.STRICT_ISOLATION:
            # Option A: STRIKTE ISOLATION - Kein Internet
            print(f"   🔒 Strikte Isolation: Nur interne Services erlaubt")
            
            # DNS und NTP explizit NICHT erlaubt
            # Spring direkt zu BLACKLIST
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_API:
            # Option B: Clearnet API-Zugriff
            print(f"   🌐 Clearnet API-Zugriff: DNS + HTTPS erlaubt")
            
            # DNS erlauben
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp --dport 53 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_DNS' "
                f"-j ACCEPT"
            ))
            
            # HTTPS (443) erlauben - Standard für APIs
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p tcp --dport 443 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_HTTPS' "
                f"-j ACCEPT"
            ))
            
            # WICHTIG: HTTP (80) ist NICHT erlaubt in CLEARNET_API
            # Grund: APIs sollten nur über verschlüsselte Verbindungen kommunizieren
            # Falls HTTP wirklich nötig ist, nutze CLEARNET_FULL
        
        elif policy.policy_type == NetworkPolicy.CLEARNET_FULL:
            # Option C: Voller Clearnet-Zugriff (wie normaler Webserver)
            print(f"   🌍 Voller Clearnet-Zugriff: DNS + HTTP/HTTPS erlaubt")
            
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
            # Option D: Nur über lokalen Tor-SOCKS-Proxy
            print(f"   🧅 Tor-Only: Nur SOCKS-Proxy auf Port {policy.tor_socks_port}")
            
            if policy.tor_socks_port > 0:
                rules.append((
                    f"-A OUTPUT -m owner --uid-owner {uid} "
                    f"-d 127.0.0.1 -p tcp --dport {policy.tor_socks_port} "
                    f"-m comment --comment 'Tenant_{config.tenant_id}_TOR_SOCKS' "
                    f"-j ACCEPT"
                ))
            else:
                print(f"   ⚠️  Tor-SOCKS-Port nicht konfiguriert!")
        
        # === PHASE 4: BLACKLIST - Explizite Blockaden (Defense in Depth) ===
        
        # Blockiere alle MySQL-Ports (außer eigenem - bereits erlaubt)
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 3306:3400 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_MySQL_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # Blockiere alle PostgreSQL-Ports (außer eigenem)
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 5432:5532 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_PostgreSQL_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # Blockiere alle PHP-FPM Ports
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-d 127.0.0.1 -p tcp --dport 9000:9200 "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Block_PHP_FPM_Range' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # === PHASE 5: DEFAULT DENY - Blockiere alles Restliche ===
        
        # TCP Default Deny
        rules.append((
            f"-A OUTPUT -m owner --uid-owner {uid} "
            f"-p tcp "
            f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_TCP' "
            f"-j REJECT --reject-with tcp-reset"
        ))
        
        # UDP Default Deny (mit Ausnahme für DNS falls erlaubt)
        if policy.allow_dns or policy.policy_type in [NetworkPolicy.CLEARNET_API, NetworkPolicy.CLEARNET_FULL]:
            # DNS wurde bereits erlaubt, blockiere Rest
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp ! --dport 53 "
                f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_UDP' "
                f"-j REJECT --reject-with icmp-port-unreachable"
            ))
        else:
            # Kein DNS erlaubt, blockiere alle UDP
            rules.append((
                f"-A OUTPUT -m owner --uid-owner {uid} "
                f"-p udp "
                f"-m comment --comment 'Tenant_{config.tenant_id}_Default_Deny_UDP_All' "
                f"-j REJECT --reject-with icmp-port-unreachable"
            ))
        
        # === REGELN ANWENDEN ===
        
        print(f"\n   Wende {len(rules)} Firewall-Regeln an...")
        for i, rule in enumerate(rules, 1):
            comment = rule.split("--comment")[1].split("'")[1] if "--comment" in rule else f"Regel_{i}"
            self._run_cmd(
                ["sudo", "iptables"] + rule.split(),
                f"   [{i:2d}/{len(rules)}] {comment}"
            )
        
        print(f"\n✅ Firewall-Regeln für {config.tenant_id} erfolgreich gesetzt")
        self._print_policy_summary(config)
    
    def _print_policy_summary(self, config: TenantConfig):
        """Zeigt Zusammenfassung der Netzwerk-Policy"""
        policy = config.network_policy
        
        print("\n" + "─" * 70)
        print(f"📋 Netzwerk-Policy für {config.tenant_id}")
        print("─" * 70)
        print(f"Policy-Typ: {policy.policy_type}")
        print("\n✅ Erlaubte Verbindungen:")
        print(f"   • 127.0.0.1:{config.mysql_port} (MySQL)")
        print(f"   • 127.0.0.1:{config.pgsql_port} (PostgreSQL)")
        
        if policy.policy_type == NetworkPolicy.STRICT_ISOLATION:
            print("\n❌ Blockiert:")
            print(f"   • Alle externen Verbindungen (kein Internet)")
            print(f"   • DNS-Lookups")
            print(f"   • Andere Tenant-Services")
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_API:
            print(f"   • *:53 (DNS)")
            print(f"   • *:443 (HTTPS)")
            print("\n❌ Blockiert:")
            print(f"   • HTTP Port 80 (nur HTTPS erlaubt)")
            print(f"   • Andere Tenant-Services")
            
        elif policy.policy_type == NetworkPolicy.CLEARNET_FULL:
            print(f"   • *:53 (DNS)")
            print(f"   • *:80,443 (HTTP/HTTPS)")
            print("\n❌ Blockiert:")
            print(f"   • Andere Tenant-Services")
            
        elif policy.policy_type == NetworkPolicy.TOR_ONLY:
            print(f"   • 127.0.0.1:{policy.tor_socks_port} (Tor SOCKS)")
            print("\n❌ Blockiert:")
            print(f"   • Direkte Internet-Verbindungen")
            print(f"   • DNS (Tor übernimmt DNS)")
            print(f"   • Andere Tenant-Services")
        
        print("─" * 70 + "\n")
    
    def _get_user_uid(self, username: str) -> Optional[int]:
        """Holt die UID eines Unix-Users"""
        try:
            return pwd.getpwnam(username).pw_uid
        except KeyError:
            return None
    
    def _print_tenant_info(self, config: TenantConfig):
        """Gibt wichtige Infos zum Tenant aus"""
        hostname_file = Path(f"/var/lib/tor/instances/{config.tenant_id}/hidden_service/hostname")
        
        onion_address = "Noch nicht generiert - warte 30 Sekunden"
        if not self.dry_run and hostname_file.exists():
            onion_address = hostname_file.read_text().strip()
        
        print("\n" + "=" * 70)
        print(f"📋 Tenant-Informationen: {config.tenant_id}")
        print("=" * 70)
        print(f"🧅 Onion-Adresse:     {onion_address}")
        print(f"🌐 Clearnet-Domain:   {config.clearnet_domain or 'Nicht konfiguriert'}")
        print(f"📁 Web-Root:          {config.web_root}/public_html")
        print(f"👤 Unix-User:         {config.unix_user}")
        print(f"🐘 PHP-FPM Port:      {config.php_fpm_port}")
        print(f"🗄️  MySQL Port:        {config.mysql_port}")
        print(f"📝 MySQL Passwort:    {self.BASE_DB_DIR}/{config.tenant_id}/mysql_root_password.txt")
        print(f"📊 Logs:              {config.web_root}/logs/")
        print("=" * 70)


# ============================================================================
# VERWENDUNG
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Multi-Tenant Micro-CMS Hosting Manager"
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--create", type=str, metavar="TENANT_ID")
    parser.add_argument("--clearnet-domain", type=str)
    parser.add_argument(
        "--network-policy",
        type=str,
        choices=["strict", "clearnet_api", "clearnet_full", "tor_only"],
        default="strict",
        help="Netzwerk-Isolation-Policy (default: strict)"
    )
    parser.add_argument("--tor-socks-port", type=int, default=0)
    
    args = parser.parse_args()
    
    manager = MultiTenantHostingManager(dry_run=args.dry_run)
    
    if args.create:
        # Automatische Port-Zuweisung (könnte aus DB kommen)
        tenant_num = hash(args.create) % 100
        
        # Network Policy konfigurieren
        network_policy = NetworkPolicy(
            policy_type=args.network_policy,
            tor_socks_port=args.tor_socks_port
        )
        
        config = TenantConfig(
            tenant_id=args.create,
            clearnet_domain=args.clearnet_domain,
            apache_port=9000 + tenant_num,
            php_fpm_port=9100 + tenant_num,
            mysql_port=3306 + tenant_num,
            pgsql_port=5432 + tenant_num,
            unix_user=f"tenant_{args.create}",
            web_root=manager.BASE_WEB_DIR / args.create,
            network_policy=network_policy
        )
        
        manager.create_tenant(config)
        
        # Policy-Beispiele ausgeben
        print("\n" + "=" * 70)
        print("📚 Weitere Policy-Beispiele:")
        print("=" * 70)
        print("\n# Strikte Isolation (Standard):")
        print(f"sudo python3 hosting_manager.py --create {args.create} --network-policy strict")
        print("\n# Clearnet API-Zugriff (DNS + HTTPS):")
        print(f"sudo python3 hosting_manager.py --create {args.create} --network-policy clearnet_api")
        print("\n# Voller Clearnet-Zugriff:")
        print(f"sudo python3 hosting_manager.py --create {args.create} --network-policy clearnet_full")
        print("\n# Nur über Tor (SOCKS-Proxy):")
        print(f"sudo python3 hosting_manager.py --create {args.create} --network-policy tor_only --tor-socks-port 9050")
        print("=" * 70 + "\n")
