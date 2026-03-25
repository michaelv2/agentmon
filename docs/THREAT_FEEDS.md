# Threat Intelligence Feeds

Agentmon can automatically download and check domains against external threat intelligence feeds from reputable sources.

## Overview

Threat feeds provide high-confidence alerts for known malicious domains (malware distribution sites, C2 servers, phishing, etc.) that may not be blocked by Pi-hole but are actively being queried by clients on your network.

**Why this matters:**
- Clients may bypass DNS filtering (hardcoded IPs, DoH/DoT)
- New threats emerge faster than Pi-hole blocklists update
- Provides defense-in-depth beyond DNS blocking

## Feed Sources

Currently integrated feeds (all from abuse.ch):

### URLhaus
- **URL:** https://urlhaus.abuse.ch/
- **Content:** Malware distribution sites, C2 servers, phishing URLs
- **Update frequency:** Daily
- **Quality:** High - actively maintained by security researchers

### CERT.PL
- **URL:** https://hole.cert.pl/domains/domains.txt
- **Content:** Malicious domains (phishing, malware, C2) identified by Poland's national CERT
- **Update frequency:** Daily
- **Quality:** High - national CERT with active incident response

## Configuration

```toml
[threat_feeds]
enabled = true

# Directory to cache downloaded feeds
cache_dir = "~/.cache/agentmon/feeds"

# How often to refresh feeds (hours)
update_interval_hours = 24

# Alert severity for threat feed matches
alert_severity = "high"
```

## Usage

### Automatic Updates

When enabled, feeds are automatically:
1. Downloaded on first startup
2. Refreshed when cache is stale (older than `update_interval_hours`)
3. Checked against every DNS query

### Manual Management

```bash
# Update feeds and show statistics
agentmon feeds
```

Output example:
```
Updating threat intelligence feeds...

Total malicious domains: 12,453

┌─────────┬─────────┬─────────────────────┬────────────┐
│ Feed    │ Domains │ Last Updated        │ Age (hours)│
├─────────┼─────────┼─────────────────────┼────────────┤
│ urlhaus │  8,234  │ 2026-01-28 14:23:15 │     2      │
│ certpl  │ 12,471  │ 2026-01-28 14:23:17 │     2      │
└─────────┴─────────┴─────────────────────┴────────────┘

Cache directory: /home/user/.cache/agentmon/feeds
```

## Alert Examples

When a client queries a domain in the threat feeds:

```
┌─────────────────────────────────────────────────────────┐
│ 🚨 HIGH - Domain in threat intelligence feed           │
├─────────────────────────────────────────────────────────┤
│ Client: alice-laptop                                    │
│ Domain: malicious-c2.com                                │
│ Time:   2026-01-28 15:42:13                             │
│                                                         │
│ Client alice-laptop queried domain 'malicious-c2.com'  │
│ which appears in threat intelligence feeds              │
│ (malware/C2/phishing)                                   │
│                                                         │
│ Analyzer: dns_baseline.threat_feed                      │
│ Confidence: 90%                                         │
│ Tags: threat_feed, external_intel                       │
└─────────────────────────────────────────────────────────┘
```

## Implementation Details

### Feed Format

Feeds are downloaded as plain text files, one domain per line:
```
malicious.com
c2-server.net
phishing-site.org
```

URLhaus also includes URLs, which are automatically parsed:
```
http://malicious.com/payload.exe
https://c2-server.net/gate.php
```

### Caching

- Feeds are cached in `~/.cache/agentmon/feeds/` by default
- Each feed is stored as `<name>.txt`
- Timestamp-based staleness checking
- Atomic updates (temp file + rename)

### Matching Algorithm

1. **Exact match:** `malicious.com` matches `malicious.com`
2. **Subdomain match:** `sub.malicious.com` matches `malicious.com`
3. **Case insensitive:** All comparisons are lowercase

### Performance

- Domains loaded into memory as a Python `set` (~1-2 MB for 10K domains)
- O(1) lookup time
- Negligible CPU impact on DNS event processing

### Security

- **Input validation:** Rejects IP addresses, validates domain format
- **Size limits:** Large feeds are still manageable (tested with 50K+ domains)
- **Network errors:** Gracefully falls back to cached version if download fails
- **No user input:** Feed sources are hardcoded (not configurable via TOML)

## Integration with Other Features

### LLM Classification

Threat feed alerts can be enriched with LLM analysis if enabled:
```toml
[llm]
enabled = true
```

The LLM may provide additional context about why the domain is malicious.

### Slack Notifications

Threat feed alerts respect the Slack severity filter:
```toml
[slack]
min_severity = "medium"  # Will include HIGH threat feed alerts
```

### Deduplication

Repeated queries to the same malicious domain are deduplicated within the configured window (default 10 minutes).

## Adding New Feed Sources

To add a new feed, edit `agentmon/threat_feeds.py`:

```python
feeds = [
    {
        "name": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "description": "URLhaus malware/C2 domains (abuse.ch)",
    },
    {
        "name": "certpl",
        "url": "https://hole.cert.pl/domains/domains.txt",
        "description": "CERT.PL malicious domains (phishing, malware, C2)",
    },
    # Add new feed here:
    {
        "name": "custom_feed",
        "url": "https://example.com/feed.txt",
        "description": "Custom threat feed",
    },
]
```

Supported formats:
- Plain text (one domain per line)
- Comments starting with `#` are ignored
- URLs are automatically parsed to extract domains

## Troubleshooting

### Feeds not updating

```bash
# Check feed status
agentmon feeds

# Manually delete cache to force refresh
rm -rf ~/.cache/agentmon/feeds/
agentmon feeds
```

### Network errors

If downloads fail (firewall, no internet):
- Agentmon will use the last cached version
- Warning logged but operation continues
- Empty cache created on first failure to prevent repeated attempts

### False positives

If a domain is incorrectly flagged:
1. Add to allowlist in config:
   ```toml
   [analyzer]
   allowlist = ["legitimate-domain.com"]
   ```
2. Report to feed source (abuse.ch has a reporting mechanism)

## Privacy Considerations

- **No data sent:** Feeds are downloaded, not uploaded
- **Local processing:** All domain checks happen locally
- **Feed sources:** abuse.ch is a reputable non-profit security organization
- **Cache location:** Default is `~/.cache` (user-private directory)

## Future Enhancements

Potential improvements:
- Configurable feed sources via TOML
- Support for IP-based feeds (currently domain-only)
- Feed categories (malware vs phishing vs C2)
- Historical feed statistics (trends over time)
- Automatic feed quality scoring
