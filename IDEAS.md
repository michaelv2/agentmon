### Here are some things we can work on that don't need live data:

#### Infrastructure
3. Systemd service for agentmon hub - run as a daemon

#### Analysis improvements
5. Batch LLM classification - classify domains in background, not blocking syslog ingestion

#### Phase 2 prep
7. OpenWRT connection tracking - store connection events (schema exists, storage doesn't)
8. DNS-to-connection correlation - link DNS lookups to subsequent connections

#### Testing
10. Integration tests - end-to-end syslog → alert flow

#### Misc
12. Re-train static rules based on LLM evaluation
13. Double-check documentation
14. Run security audit one more time before GitHub push

#### Later
15. Clawdbot!