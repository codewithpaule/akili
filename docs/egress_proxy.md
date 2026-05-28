**Egress Proxy & SSRF Mitigation**

- Use an egress proxy or dedicated NAT gateway to control outbound connections from the app and workers.
- Recommended steps:
  - Deploy a forward proxy (e.g., Squid, Envoy) in the same VPC and configure app/worker to route HTTP(S) through it.
  - Apply allowlist rules at the proxy level for `AGENT_ALLOWED_HOSTS` and block private/internal CIDR ranges.
  - Log all outgoing requests and apply rate limits per-identity to detect abuse.
- Fly.io note: Use a private network or dedicated VPC connector + egress appliance if available.
- Monitoring: Export proxy logs to a central logging stack (ELK/Datadog) and set alerts for spikes.
