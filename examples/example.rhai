// Example dnsforge zone definition
//
// Usage:
//   dnsforge apply example.rhai
//   dnsforge apply --dry-run example.rhai
//   dnsforge check example.rhai

// Set the DNS server for all zones in this file
server("ns.example.com");

// Define a zone with its TSIG key name (must exist in the keystore)
zone("example.com", "my-tsig-key");

// SOA record (serial is managed automatically)
ttl(86400);
soa("ns1.example.com.", "hostmaster.example.com.", #{
    refresh: 43200,
    retry: 7200,
    expire: 1209600,
    minimum: 3600,
});

// Name servers
ns("ns1.example.com.");
ns("ns2.example.com.");

// Mail
ttl(3600);
mx("@", 10, "mail.example.com.");
txt("@", "v=spf1 mx ~all");
txt("_dmarc", "v=DMARC1; p=quarantine");

// Web servers
a("@", "203.0.113.1");
a("@", "203.0.113.2");
aaaa("@", "2001:db8::1");

// Services
a("mail", "203.0.113.10");
cname("www", "example.com.");
cname("docs", "example.com.");

// Using loops for multiple similar records
for alias in ["api", "app", "cdn"] {
    cname(alias, "lb.example.com.");
}

// Using environment variables
if env("STAGING_IP") != () {
    a("staging", env("STAGING_IP"));
}

// Externally managed records (won't be deleted if present)
keep("_acme-challenge", "TXT");
keep("_25._tcp.mail", "TLSA");

// SRV records
srv("_sip._tcp", 10, 60, 5060, "sip.example.com.");

// CAA record
caa("@", "issue", "letsencrypt.org");
