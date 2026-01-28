# Edge Device Setup for Syslog Push

This guide explains how to configure your edge devices (Pi-hole, OpenWRT) to push logs to agentmon via syslog.

## Architecture

```
┌─────────────┐  syslog    ┌─────────────┐
│   Pi-hole   │ ─────────> │             │
└─────────────┘    TCP     │   agentmon  │
                  :1514    │     hub     │
┌─────────────┐            │             │
│   OpenWRT   │ ─────────> │             │
└─────────────┘            └─────────────┘
```

**Benefits over SSH pull:**
- Hub holds no credentials to network infrastructure
- Real-time event streaming (no polling delay)
- Works behind NAT (devices push outbound)
- Lower overhead on edge devices

## Starting the Receiver

On your agentmon hub:

```bash
# Basic usage (TCP on port 1514 - default)
agentmon listen

# Explicit port and protocol
agentmon listen --port 1514 --protocol tcp

# Restrict to specific source IPs
agentmon listen --allow 192.168.1.2 --allow 192.168.1.3

# Learning mode (build baseline without alerting)
agentmon listen --learning

# Verbose output (show each message)
agentmon listen -v
```

## Pi-hole Configuration

Pi-hole logs DNS queries to its own log file (`/var/log/pihole/pihole.log`) rather than syslog.
The recommended approach is to use a simple systemd service that tails the log and forwards via logger.

### Recommended: systemd Service (tail + logger)

This method is more reliable than rsyslog's imfile module, which can have buffering issues with pihole-FTL.

Create the service file:

```bash
sudo nano /etc/systemd/system/agentmon-forward.service
```

Add the following (replace `<hub-ip>` with your agentmon hub's IP):

```ini
[Unit]
Description=Forward Pi-hole logs to agentmon
After=network.target pihole-FTL.service

[Service]
Type=simple
ExecStart=/bin/sh -c 'tail -F /var/log/pihole/pihole.log | logger -t pihole -n <hub-ip> -P 1514 --tcp'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable agentmon-forward
sudo systemctl start agentmon-forward

# Check status
sudo systemctl status agentmon-forward
```

**To find your Pi-hole log location:**
```bash
ls -la /var/log/pihole*/pihole.log /var/log/pihole.log 2>/dev/null
```

### Verify

Check that logs are being forwarded:

```bash
# On Pi-hole - generate a DNS query
nslookup example.com localhost

# On agentmon hub - should see the query
agentmon listen -v
```

### Alternative: rsyslog (imfile)

**Note:** rsyslog's imfile module may have buffering issues with pihole-FTL's log writes. The systemd service above is more reliable. Use this only if you prefer rsyslog-based configuration.

Create a new rsyslog configuration file:

```bash
sudo nano /etc/rsyslog.d/99-agentmon.conf
```

Add the following (replace `<hub-ip>` with your agentmon hub's IP):

```
# Load the file input module
module(load="imfile")

# Watch Pi-hole log file and forward new entries
input(type="imfile"
      File="/var/log/pihole/pihole.log"
      Tag="pihole"
      Facility="local0"
      Severity="info"
      freshStartTail="on")

# Forward to agentmon via TCP
if $syslogtag startswith 'pihole' then @@<hub-ip>:1514
```

**Note:** `freshStartTail="on"` ensures rsyslog only forwards new log entries, not the entire history. Use `startswith` for the tag match since imfile appends a colon to tags.

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

### Alternative: syslog-ng

If using syslog-ng instead of rsyslog:

```
# /etc/syslog-ng/conf.d/agentmon.conf
source s_pihole {
    file("/var/log/pihole/pihole.log" follow-freq(1));
};

destination d_agentmon {
    tcp("<hub-ip>" port(1514));
};

log {
    source(s_pihole);
    destination(d_agentmon);
};
```

## OpenWRT Configuration

### Via UCI (Command Line)

```bash
# Configure remote syslog
uci set system.@system[0].log_ip='<hub-ip>'
uci set system.@system[0].log_port='1514'
uci set system.@system[0].log_proto='tcp'

# Enable conntrack logging (optional - for connection events)
uci set system.@system[0].log_type='both'

# Apply changes
uci commit system
/etc/init.d/log restart
```

### Via LuCI (Web Interface)

1. Go to **System → System → Logging**
2. Set **External system log server**: `<hub-ip>`
3. Set **External system log server port**: `1514`
4. Set **External system log server protocol**: `TCP`
5. Click **Save & Apply**

### Firewall Logging (Optional)

To log blocked/rejected connections:

```bash
# Edit /etc/config/firewall
uci set firewall.@defaults[0].log='1'
uci set firewall.@defaults[0].log_limit='10/minute'

# Apply
uci commit firewall
/etc/init.d/firewall restart
```

Or edit `/etc/config/firewall` directly:

```
config defaults
    option log '1'
    option log_limit '10/minute'
```

## Firewall Rules

If you have a firewall between edge devices and the hub, allow syslog traffic:

### On agentmon hub (iptables)

```bash
# Allow UDP syslog
iptables -A INPUT -p udp --dport 1514 -j ACCEPT

# Allow TCP syslog (if using TCP)
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
```

### On agentmon hub (ufw)

```bash
ufw allow 1514/udp
ufw allow 1514/tcp  # if using TCP
```

### On agentmon hub (firewalld)

```bash
firewall-cmd --add-port=1514/udp --permanent
firewall-cmd --add-port=1514/tcp --permanent  # if using TCP
firewall-cmd --reload
```

## Running as a Service

### systemd Service

Create `/etc/systemd/system/agentmon-listen.service`:

```ini
[Unit]
Description=Agentmon Syslog Receiver
After=network.target

[Service]
Type=simple
User=agentmon
ExecStart=/usr/local/bin/agentmon listen --port 1514
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable agentmon-listen
sudo systemctl start agentmon-listen

# Check status
sudo systemctl status agentmon-listen
```

## Security Considerations

### Use an IP Allowlist

Restrict which IPs can send syslog messages:

```bash
agentmon listen --port 1514 --allow 192.168.1.2 --allow 192.168.1.3
```

### Bind to Specific Interface

Bind to the hub's specific IP instead of all interfaces:

```bash
# Replace with your hub's LAN IP
agentmon listen --bind 192.168.1.100
```

This prevents listening on other interfaces (e.g., public-facing NICs).

**Note:** If running in WSL2 with port forwarding, `--bind` has limited effect since traffic arrives via the Windows NAT gateway. Use Windows Firewall for access control instead.

### Syslog is Unencrypted

Standard syslog (UDP/TCP) is not encrypted. If forwarding across untrusted networks:

1. **Use a VPN** (WireGuard, OpenVPN) between edge devices and hub
2. **Use TLS** (rsyslog RELP with TLS, or syslog-ng TLS transport)
3. **Use SSH tunnel** as a fallback

Example SSH tunnel from edge device:

```bash
# On edge device, forward local syslog to hub via SSH
ssh -N -L 1514:localhost:1514 user@<hub-ip>
```

## Troubleshooting

### No Messages Received

1. Check the receiver is running:
   ```bash
   agentmon listen -v
   ```

2. Test connectivity from edge device:
   ```bash
   nc -zv <hub-ip> 1514
   ```

3. Test with a manual message (from edge device):
   ```bash
   echo "<30>Jan 27 12:00:00 pihole dnsmasq[1234]: query[A] test.example.com from 192.168.1.100" | nc <hub-ip> 1514
   ```

4. Check firewall rules on both ends

5. Verify edge device configuration:
   ```bash
   # On Pi-hole (systemd service)
   sudo systemctl status agentmon-forward
   journalctl -u agentmon-forward -f

   # On Pi-hole (rsyslog alternative)
   cat /etc/rsyslog.d/99-agentmon.conf
   sudo rsyslogd -N1  # Check for config errors

   # On OpenWRT
   uci show system | grep log
   ```

### Pi-hole: Manual Test Works but DNS Queries Don't

If using the systemd service (recommended):

1. Check the service is running:
   ```bash
   sudo systemctl status agentmon-forward
   ```

2. Check the log file path exists and is readable:
   ```bash
   ls -la /var/log/pihole*/pihole.log /var/log/pihole.log 2>/dev/null
   ```

3. Restart the service:
   ```bash
   sudo systemctl restart agentmon-forward
   ```

If using rsyslog (imfile), this usually means rsyslog isn't tailing the Pi-hole log correctly due to buffering issues with pihole-FTL. Consider switching to the systemd service method instead.

### Flood of Old Messages (rsyslog only)

rsyslog is replaying historical log entries. This happens when `freshStartTail="on"` is missing or rsyslog state was cleared while the log file has history.

Fix:
```bash
sudo systemctl stop rsyslog
sudo rm -f /var/spool/rsyslog/imfile-state:*
# Optionally truncate the log to start fresh:
# sudo truncate -s 0 /var/log/pihole/pihole.log
sudo systemctl start rsyslog
```

**Note:** The systemd service (tail + logger) method doesn't have this problem since `tail -F` only follows new lines by default.

### Messages Received but Not Parsed

Run in verbose mode to see raw messages:

```bash
agentmon listen -v
```

Check that the message format matches expected patterns. Pi-hole log format (in pihole.log):
```
Jan 28 01:14:11 dnsmasq[6587]: query[A] example.com from 192.168.1.100
```

When forwarded via tail | logger, it becomes:
```
<134>Jan 28 01:14:11 pi-hole pihole: Jan 28 01:14:11 dnsmasq[6587]: query[A] example.com from 192.168.1.100
```

### High CPU Usage

If receiving high message volume:
- If using rsyslog, ensure `freshStartTail="on"` is set (prevents log replay)
- The systemd service method is lightweight and handles high volume well
- Consider filtering at the source (only forward query lines)
- For very high volume, batch processing may help (future feature)

## Testing

### Send Test Message

```bash
# Test TCP connectivity
nc -zv <hub-ip> 1514

# Send a simulated Pi-hole DNS query (format from tail | logger)
echo "<134>Jan 28 14:32:15 pi-hole pihole: Jan 28 14:32:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100" | nc <hub-ip> 1514

# Simpler format (also works)
echo "<30>Jan 28 14:32:15 pihole pihole: dnsmasq[1234]: query[A] example.com from 192.168.1.100" | nc <hub-ip> 1514
```

### Verify on Hub

Watch for incoming messages:
```bash
agentmon listen -v
```

### Verify in Database

After collecting real traffic:

```bash
agentmon stats --hours 1
agentmon baseline
```
