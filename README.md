# Tor Isolation Layer (TIL)

A native multi-tenant isolation framework for high-security hosting environments.
Designed for dual-stack operations across clearnet and Tor hidden services.
Provides strict per-tenant separation for web, PHP-FPM, MySQL, PostgreSQL and networking layers.

## Overview

TIL provisions fully isolated hosting containers without using containers.
Each tenant receives its own user, filesystem, PHP-FPM pool, MySQL instance, PostgreSQL instance, Apache vHost and Tor Hidden Service.
All tenants operate under hardened systemd units, private sockets and individualized port spaces.

This system targets operators who require reproducible, deterministic segregation of workloads on a single host without virtualization overhead.

## Architecture

* Dedicated Unix user per tenant
* Dedicated directory tree with enforced permissions
* One PHP-FPM pool per tenant
* Per-tenant MySQL and PostgreSQL instances (own datadir, own sockets, own systemd service)
* Apache VirtualHost for Tor + optional clearnet domain
* Automatic Tor Hidden Service provisioning
* Strict firewall policy per tenant
* Optional network caps: strict, Tor-only, clearnet-API, or full outbound

No shared sockets. No shared memory pools. No cross-tenant PHP temp dirs.
All processes run under isolated systemd units with hardened sandboxing options.

## Network Isolation Model

Policies define outbound capabilities per tenant:

* strict — no outbound traffic
* tor_only — all outbound resolved through tenant-local Tor SOCKS
* clearnet_api — HTTPS-only to whitelisted domains
* clearnet_full — standard HTTP/HTTPS without domain restrictions

Each policy enforces DNS, NTP, socket binding, and domain whitelist behavior.

## Features

* Automatic provisioning of MySQL and PostgreSQL with isolated datadirs
* Auto-generated systemd service files for each database instance
* Per-tenant PHP-FPM configuration with locked-down directives
* Full Tor service lifecycle: torrc generation, directory prep, permissions
* Hardened systemd constraints (ProtectSystem, PrivateTmp, NoNewPrivileges, etc.)
* Deterministic port assignment
* Logging separation for PHP, Apache, MySQL, PostgreSQL

## Requirements

* Debian or Ubuntu environment
* Apache2 with proxy_fcgi enabled
* PHP-FPM 8.2 (adjust path if needed)
* MySQL or MariaDB server tools
* PostgreSQL binaries (adjust version paths)
* Tor with multi-instance support
* systemd

Root access is mandatory for provisioning.

## Usage

Import the classes and create a `TenantConfig`.
Call `create_tenant()` on `MultiTenantHostingManager`.

Minimal example:

```python
from til import TenantConfig, NetworkPolicy, MultiTenantHostingManager
from pathlib import Path

cfg = TenantConfig(
    tenant_id="tenant1",
    clearnet_domain=None,
    apache_port=8081,
    php_fpm_port=9001,
    mysql_port=3307,
    pgsql_port=5433,
    unix_user="tenant_t1",
    web_root=Path("/var/www/tenants/tenant1"),
    network_policy=NetworkPolicy(policy_type=NetworkPolicy.TOR_ONLY)
)

manager = MultiTenantHostingManager(dry_run=False)
manager.create_tenant(cfg)
```

This executes the entire provisioning chain end-to-end.

## Security Considerations

* All tenants run under dedicated system users
* No shell login
* No global socket exposure
* No shared PHP pool
* Database instances restricted to localhost
* Tor hidden services isolated under dedicated torrc directories
* Privilege boundaries enforced via systemd hardening
* No outbound internet unless policy explicitly allows it

This framework assumes you understand Linux privilege separation, systemd, Tor, SQL servers, and web stack isolation.

## License

This project is licensed under **GPLv3**.
You must retain the copyright notice.
Derivative work must also be released under GPLv3 and published with full source.

#### copyright
> Volkan Kücükbudak
