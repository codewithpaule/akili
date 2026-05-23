class AkiliClient {
  constructor(apiKey, sandbox = false, baseUrl = null) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl || (sandbox ? 'https://api.akili.io/v1/sandbox' : 'https://api.akili.io/v1');
  }

  async scanWebsite(url) {
    const res = await fetch(`${this.baseUrl}/scan/website`, {
      method: 'POST',
      headers: { 'X-API-Key': this.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch { return { raw: text }; }
  }

  async searchPerson(name, keywords = '') {
    const res = await fetch(`${this.baseUrl}/scan/person`, {
      method: 'POST',
      headers: { 'X-API-Key': this.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, keywords }),
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch { return { raw: text }; }
  }

  async getReport(scanId) {
    const res = await fetch(`${this.baseUrl}/report/${scanId}`, {
      headers: { 'X-API-Key': this.apiKey },
    });
    return res.json();
  }
}

export default AkiliClient;
