/* Helper: duplicate scan pages — configs for each module */
window.AKILI_SCAN_CONFIGS = {
  vulnerability: { endpoint: '/api/v1/scan/vulnerability', field: 'url', placeholder: 'https://example.com', color: 'var(--mod-vuln)', title: 'Vulnerability Assessment' },
  subdomains: { endpoint: '/api/v1/scan/subdomains', field: 'domain', placeholder: 'example.com', color: 'var(--mod-subdomain)', title: 'Subdomain Discovery' },
  ip: { endpoint: '/api/v1/scan/ip', field: 'ip', placeholder: '8.8.8.8', color: 'var(--mod-ip)', title: 'IP Intelligence' },
  organization: { endpoint: '/api/v1/scan/organization', fields: ['name', 'domain'], color: 'var(--mod-org)', title: 'Organization Scan' },
  company: { endpoint: '/api/v1/scan/company', fields: ['name', 'domain'], color: 'var(--mod-company)', title: 'Company Intel' },
  email: { endpoint: '/api/v1/scan/email', field: 'email', placeholder: 'user@example.com', color: 'var(--mod-email)', title: 'Email Investigator' },
  domain: { endpoint: '/api/v1/scan/domain', field: 'domain', placeholder: 'example.com', color: 'var(--mod-domain)', title: 'Domain Reputation' },
};
