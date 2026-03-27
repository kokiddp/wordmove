# Wordmove

![logo](https://raw.githubusercontent.com/welaika/wordmove/master/assets/images/wordmove.png)

This fork keeps Wordmove usable on current Ruby, OpenSSL, MariaDB, and Docker-based WordPress setups while preserving the original workflow and Movefile format.

[![Tests](https://github.com/kokiddp/wordmove/actions/workflows/ruby.yml/badge.svg)](https://github.com/kokiddp/wordmove/actions/workflows/ruby.yml)

## What This Fork Changes

- Runs on modern Ruby versions, including Ruby 3.4 and the current Ruby 4.0 CI line.
- Fixes `net-ssh` and OpenSSL 3 incompatibilities that break SSH connections on newer Rubies.
- Prefers `mariadb` and `mariadb-dump` when available, while still falling back to `mysql` and `mysqldump`.
- Handles MariaDB dump "sandbox mode" headers during import.
- Normalizes unsupported collations and charset declarations in SQL dumps before import.
- Uses `wp-cli` in a Docker-friendly way with `--allow-root`.
- Prints concise command summaries instead of dumping long multi-line shell wrappers to the console.

## Changelog Since `bc9bce6`

- Ruby compatibility:
  - The repo default Ruby is now `3.4.9`.
  - The GitHub Actions matrix now tests `2.6`, `2.7`, `3.0`, `3.1`, `3.2`, `3.3`, `3.4`, and `4.0`.
  - Runtime dependencies were updated for modern Ruby packaging and stdlib extraction: `thor`, `base64`, `bigdecimal`, `mutex_m`, `ed25519`, and `bcrypt_pbkdf`.
  - `Movefile` YAML loading now works across older and newer Psych versions.
  - `bin/console` now falls back to `irb` when `pry` is unavailable on newer Rubies.

- SSH and OpenSSL 3:
  - Added a compatibility layer for `net-ssh 6.1` on OpenSSL 3.
  - Fixes cover EC, RSA, and DSA host key parsing plus ECDH and DH key generation.
  - This removes the common Ruby 3.4/OpenSSL 3 crashes seen during SSH deploys and DB sync.

- Database sync behavior:
  - Dump commands now auto-detect `mariadb-dump` or `mysqldump`.
  - Import commands now auto-detect `mariadb` or `mysql`.
  - Movefiles can now express unix socket connections with `database.socket`.
  - Legacy `--socket` usage inside `mysql_options` and `mysqldump_options` is still supported.
  - Imports strip the MariaDB sandbox header when present, append a trailing `COMMIT;`, enable `--binary-mode`, disable foreign key checks, and preserve exit status correctly.
  - Existing `mysql_options` are respected without duplicating `--binary-mode`.

- SQL dump normalization:
  - Added built-in collation fallbacks for newer `utf8mb3` collations that older targets may not understand.
  - Added built-in charset fallback from `utf8mb3` to `utf8mb4`.
  - These mappings can be overridden in `movefile.yml`.

- WP-CLI and hooks:
  - `wp cli param-dump` now uses `--allow-root`, which avoids failures in root-owned Docker or containerized environments.
  - Hook working directories are now shell-escaped more safely.

- Logging and developer experience:
  - Long generated shell scripts are summarized as meaningful actions such as SQL dump, import, compression, and `wp search-replace`.
  - New specs cover logger summaries and the OpenSSL/SSH compatibility layer.

## Installation

This fork is typically installed directly from GitHub:

```bash
gem install specific_install
gem specific_install https://github.com/kokiddp/wordmove.git
```

For development from a checkout:

```bash
bundle install
bundle exec exe/wordmove --help
```

## Supported Ruby Versions

- Local default in this repository: `3.4.9`
- CI coverage: `2.6`, `2.7`, `3.0`, `3.1`, `3.2`, `3.3`, `3.4`, `4.0`
- Minimum declared Ruby version in the gemspec: `2.6.0`

## Peer Dependencies

Wordmove is orchestration glue. These tools still need to exist in your environment and be available in `$PATH`.

| Program | Mandatory? | Notes |
| --- | --- | --- |
| `rsync` | Yes for SSH protocol | Used for file sync |
| `mysql` or `mariadb` | Yes | Used for DB import and checks |
| `mysqldump` or `mariadb-dump` | Yes | Used for DB export |
| `wp` | Yes by default | Required by the default `wpcli` SQL adapter |
| `lftp` | Yes for FTP/SFTP | Only needed for FTP/SFTP setups |

Remote hosts are also expected to provide `gzip`, `nice`, `rsync`, and either `mysql`/`mariadb` plus `mysqldump`/`mariadb-dump` when database sync happens over SSH.

## Quick Start

```bash
wordmove init
wordmove doctor
wordmove pull -e staging -d
wordmove push -e production --all
```

Run `wordmove help` to see all commands and flags.

## `movefile.yml`

Basic example:

```yaml
global:
  sql_adapter: wpcli

local:
  vhost: http://vhost.local
  wordpress_path: /home/john/sites/your_site

  database:
    name: database_name
    user: user
    password: password
    host: localhost

production:
  vhost: https://example.com
  wordpress_path: /var/www/your_site

  database:
    name: database_name
    user: user
    password: password
    host: host
    # port: 3308
    # socket: /path/to/mysql.sock
    # mysqldump_options: --max_allowed_packet=50MB
    # mysql_options: --protocol=TCP

  exclude:
    - ".git/"
    - ".gitignore"
    - "node_modules/"
    - "bin/"
    - "tmp/*"
    - "Gemfile*"
    - "Movefile"
    - "movefile"
    - "movefile.yml"
    - "movefile.yaml"
    - "wp-config.php"
    - "wp-content/*.sql.gz"
    - "*.orig"

  ssh:
    host: host
    user: user
```

Multi-environment Movefiles are still supported. Any first-level key other than `global` and `local` is treated as a remote environment. Use `-e staging`, `-e production`, and so on.

## Environment Variables

Movefiles support ERB, so secrets can be loaded from the shell or from `.env` files.

```yaml
production:
  database:
    user: "<%= ENV['PROD_DB_USER'] %>"
    password: "<%= ENV['PROD_DB_PASS'] %>"
```

You can populate those variables either in the shell:

```bash
export PROD_DB_USER="username"
export PROD_DB_PASS="password"
```

or in a `.env` file next to the Movefile:

```bash
PROD_DB_USER="username"
PROD_DB_PASS="password"
```

## SQL Import and Dump Compatibility

This fork changes DB import/export behavior in a few important ways:

- MariaDB client binaries are preferred automatically when present.
- You can now configure unix socket connections directly as `database.socket: /path/to/mysqld.sock`.
- The older `--socket ...` form inside `database.mysql_options` or `database.mysqldump_options` still works and remains backward-compatible.
- Dumps beginning with:

```sql
/*!999999- enable the sandbox mode */
```

  are imported correctly by stripping that header before the actual import.
- Imports append a final `COMMIT;` to reduce partial transaction edge cases.
- Imports enable `SET FOREIGN_KEY_CHECKS=0` and `--binary-mode` unless you already configured binary mode explicitly.

These changes are especially useful when moving databases between Local, Docker, MariaDB 11+, and older shared-hosting MySQL servers.

Example:

```yaml
local:
  database:
    name: local
    user: root
    password: root
    host: localhost
    socket: /home/koki/.config/Local/run/eZGRlahhA/mysql/mysqld.sock
```

When `wordmove init` reads a `wp-config.php` entry like:

```php
define('DB_HOST', 'localhost:/home/koki/.config/Local/run/eZGRlahhA/mysql/mysqld.sock');
```

it now generates separate `host` and `socket` fields in the Movefile instead of leaving the combined value inside `host`.

Likewise, when `DB_HOST` contains a custom port such as:

```php
define('DB_HOST', 'localhost:3307');
```

`wordmove init` now generates separate `host` and `port` fields and uncomments the local `port` line in the generated Movefile.

## Collation Fallbacks

If your source dump contains collations unsupported by the destination server, Wordmove can rewrite them before import.

Default behavior already normalizes newer `utf8mb3` collations such as:

- `utf8mb3_uca1400_ai_ci`
- `utf8mb3_uca1400_as_cs`
- `utf8mb3_unicode_520_ci`

to `utf8mb4_unicode_ci`, and upgrades `utf8mb3` to `utf8mb4`.

You can override the defaults in `movefile.yml`:

```yaml
global:
  collation_fallbacks:
    utf8mb3_uca1400_ai_ci: utf8mb4_unicode_ci
    utf8mb3_uca1400_as_cs: utf8mb4_unicode_ci

  charset_fallbacks:
    utf8mb3: utf8mb4
```

## Docker and Root-Owned WordPress Installs

The default `wpcli` adapter now calls `wp cli param-dump --allow-root --with-values`, which makes path discovery and search-replace flows work better in containerized environments where `wp` runs as `root`.

## Logging

Long generated shell wrappers are summarized into shorter, more useful task lines. For example, instead of printing the full multi-line SQL import script, Wordmove now logs intent-oriented summaries such as:

- `dump database my_db to ./wp-content/dump.sql`
- `compress ./wp-content/dump.sql`
- `wp search-replace old.example.test -> new.example.test in ./public`
- `import SQL dump ./wp-content/dump.sql into database local (strip sandbox header, append COMMIT)`

This keeps normal output readable without hiding what Wordmove is actually doing.

## Usage Notes

### Mirroring

File push and pull operations mirror the source. Files missing from the source can be deleted on the destination. Exclude anything you need to preserve.

### SSH

- `rsync` must be installed locally.
- SSH public key authentication is still the recommended setup.
- Passwords inside `movefile.yml` may still work, but key-based auth is strongly preferred.

### FTP and SFTP

- `lftp` is required locally.
- Use the relative FTP path as `production.wordpress_path`.
- Use `production.wordpress_absolute_path` when the server layout requires it.
- FTP support remains available, but upstream development for FTP has long been discontinued.

## Upstream Documentation

Most of the original Wordmove workflow and Movefile format still match the upstream documentation:

- [Usage and flags explained](https://github.com/welaika/wordmove/wiki/Usage-and-flags-explained)
- [Multiple environments explained](https://github.com/welaika/wordmove/wiki/Multiple-environments-explained)
- [Movefile configuration explained](https://github.com/welaika/wordmove/wiki/movefile.yml-configurations-explained)
- [Hooks](https://github.com/welaika/wordmove/wiki/Hooks)

Where this README and the upstream wiki disagree, this README describes the behavior of this fork.

## Contributing

```bash
bundle exec rspec
```

The project CI currently runs the suite across:

- `2.6`
- `2.7`
- `3.0`
- `3.1`
- `3.2`
- `3.3`
- `3.4`
- `4.0`

Please keep the README updated when changing user-facing behavior, installation steps, supported versions, or command output.

## Credits

- The dump script is based on the [`MYSQL-dump` PHP package](https://github.com/dg/MySQL-dump) by David Grudl.
- The import script uses the [BigDump](http://www.ozerov.de/bigdump/) library.
- Original project by [weLaika](https://dev.welaika.com).
