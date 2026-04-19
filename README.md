# dnsforge

Declarative DNS zone manager. Define your DNS zones in [Rhai](https://rhai.rs/) scripts, and dnsforge will compute the diff against the live zone (via AXFR) and apply changes (via RFC 2136 dynamic updates).

## Features

- **Declarative zone definitions** in Rhai scripts with loops, conditionals, environment variables
- **Automatic diffing** against live zone state via AXFR zone transfer
- **Atomic updates** via RFC 2136 with TSIG authentication
- **Split-horizon DNS** support (multiple views per zone with different TSIG keys)
- **Externally managed records** preserved with `keep()` rules
- **Interactive confirmation** by default, with `--dry-run` and `--no-confirm` modes
- **Encrypted key storage** with argon2id + AES-256-GCM, password caching across keys
- **Cross-platform** (Linux, macOS, Windows)

## Installation

### From source

```sh
cargo install --path .
```

### Arch Linux

```sh
makepkg -si
```

### Debian/Ubuntu

```sh
dpkg -i dnsforge_<version>-1_<arch>.deb
```

## Quick start

### 1. Import a TSIG key

```sh
dnsforge key add /path/to/tsig-key.conf
```

The key file should be in BIND format:

```
key "my-key" {
    algorithm hmac-sha256;
    secret "base64secret==";
};
```

You'll be prompted for an encryption password. Press Enter to skip encryption.

### 2. Create a zone definition

Create `example.com.rhai`:

```rhai
server("ns.example.com");
zone("example.com", "my-key");

ttl(86400);
soa("ns1.example.com.", "hostmaster.example.com.", #{
    refresh: 43200,
    retry: 7200,
    expire: 1209600,
    minimum: 3600,
});
ns("ns1.example.com.");
ns("ns2.example.com.");

ttl(3600);
a("@", "203.0.113.1");
aaaa("@", "2001:db8::1");
mx("@", 10, "mail.example.com.");
txt("@", "v=spf1 mx ~all");

cname("www", "example.com.");
```

### 3. Preview and apply

```sh
# Show what would change
dnsforge apply --dry-run example.com.rhai

# Apply interactively (prompts for confirmation)
dnsforge apply example.com.rhai

# Apply without confirmation (for cron/CI)
dnsforge apply --no-confirm example.com.rhai
```

## Usage

```
dnsforge <COMMAND>

Commands:
  apply    Synchronize DNS zones
  check    Validate zone files without connecting
  key      Manage TSIG keys

Apply options:
  -n, --dry-run      Show changes without applying
  --no-confirm       Apply without confirmation prompt
  --zone <NAME>      Only sync named zone(s) (repeatable)

Global options:
  -v, --verbose      Increase verbosity (-v, -vv, -vvv)
  --color <WHEN>     auto, always, never [default: auto]

Key management:
  dnsforge key add [FILE] [--name NAME]   Import TSIG key
  dnsforge key list                       List stored keys
  dnsforge key remove <NAME>              Remove a key
```

## Zone definition reference

Zone files are [Rhai](https://rhai.rs/) scripts with built-in DNS functions.

### Setup

```rhai
server("ns.example.com");               // DNS server address
zone("example.com", "key-name");         // Zone with TSIG key reference
zone("example.com", "key-name", "view"); // Zone with view (split-horizon)
ttl(3600);                               // Set default TTL
```

### Record types

```rhai
soa("ns1.example.com.", "admin.example.com.", #{
    refresh: 43200, retry: 7200, expire: 1209600, minimum: 3600,
});

a("name", "192.0.2.1");
aaaa("name", "2001:db8::1");
cname("name", "target.example.com.");
mx("name", 10, "mail.example.com.");
ns("ns1.example.com.");                  // NS for zone apex
ns("sub", "ns1.example.com.");           // NS for subdomain
txt("name", "single string value");
txt("name", "string1", "string2");       // Multi-string TXT (up to 4)
srv("_sip._tcp", 10, 60, 5060, "sip.example.com.");
caa("name", "issue", "letsencrypt.org");
```

### Externally managed records

Records marked with `keep()` will not be deleted even if they're not in the zone definition:

```rhai
keep("_acme-challenge", "TXT");
keep("_25._tcp.mail", "TLSA");
```

### SOA handling

The SOA serial is managed automatically: dnsforge preserves the current serial from the server and only updates SOA if other fields (mname, rname, refresh, retry, expire, minimum, TTL) change.

### Scripting features

```rhai
// Loops
for alias in ["www", "api", "cdn"] {
    cname(alias, "lb.example.com.");
}

// Variables and maps
let servers = [
    #{ name: "web1", ip: "203.0.113.1" },
    #{ name: "web2", ip: "203.0.113.2" },
];
for s in servers {
    a(s.name, s.ip);
}

// Environment variables
if env("STAGING_IP") != () {
    a("staging", env("STAGING_IP"));
}
let ttl_val = env("DNS_TTL", "3600");  // With default

// Functions for shared records
fn mail_records() {
    mx("@", 10, "mail1.example.com.");
    mx("@", 10, "mail2.example.com.");
    txt("@", "v=spf1 mx ~all");
}

// Split-horizon with shared logic
zone("example.com", "internal-key", "internal");
mail_records();
a("@", "10.0.0.1");

zone("example.com", "external-key", "external");
mail_records();
a("@", "203.0.113.1");
```

## Key management

TSIG keys are stored in `$XDG_DATA_HOME/dnsforge/keys.txt` (typically `~/.local/share/dnsforge/keys.txt`).

```sh
# Import from BIND key file
dnsforge key add keyfile.conf

# Import with a custom reference name
dnsforge key add keyfile.conf --name my-alias

# Import from stdin
cat keyfile.conf | dnsforge key add

# List keys
dnsforge key list

# Remove a key
dnsforge key remove my-key
```

When importing, you're prompted for an encryption password. If multiple encrypted keys share the same password, you only need to enter it once per session.

## License

MIT
