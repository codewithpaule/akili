# AKILI Browser Extension Installation Guide

## How to Install the Extension

### Chrome/Edge/Brave (Chromium-based browsers)

1. **Navigate to Extensions Page**
   - Open Chrome/Edge/Brave
   - Go to `chrome://extensions/` (or `edge://extensions/` for Edge)

2. **Enable Developer Mode**
   - Toggle the "Developer mode" switch in the top right corner

3. **Load the Extension**
   - Click the "Load unpacked" button
   - Navigate to the `browser-extension` folder in your AKILI project
   - Select the folder and click "Select Folder"

4. **Verify Installation**
   - You should see "AKILI Security" in your extensions list
   - The eye icon should appear in your browser toolbar

### Firefox

1. **Navigate to Add-ons Page**
   - Open Firefox
   - Go to `about:debugging#/runtime/this-firefox`

2. **Load Temporary Add-on**
   - Click "Load Temporary Add-on"
   - Navigate to the `browser-extension` folder
   - Select `manifest.json`
   - Click "Open"

3. **Note for Firefox**
   - Temporary add-ons will be removed when you close Firefox
   - For permanent installation, you'll need to package the extension and submit to the Firefox Add-ons store

## Using the Extension

### First-Time Setup

1. **Get an API Key**
   - Visit `https://akili.com.ng/developer`
   - Sign up and generate an API key

2. **Configure the Extension**
   - Click the AKILI eye icon in your browser toolbar
   - Enter your API key in the settings
   - Click "Save API Key"

### Scanning Websites

1. **Visit any website**
2. **Click the AKILI eye icon** in your browser toolbar
3. **The extension will automatically:**
   - Scan the current page for security issues
   - Display a security score (A-F)
   - Show top findings and vulnerabilities
   - Display a corner badge with the grade (disappears after 5 seconds)

### Features

- **Real-time Scanning**: Scan any page you visit
- **Security Grade**: Get an A-F security score
- **Vulnerability Detection**: Identify CVEs and security issues
- **Corner Badge**: Quick visual indicator of page security
- **Caching**: Results cached for 1 hour to reduce API calls

### Troubleshooting

**Extension not loading:**
- Ensure you're loading the correct folder (the one containing `manifest.json`)
- Check browser console for errors (F12 → Console)

**API key not working:**
- Verify your API key is valid at `https://akili.com.ng/developer`
- Ensure the API key has the correct permissions

**Scanning not working:**
- Check if the website is accessible
- Verify your API key has sufficient quota
- Check browser console for error messages

## Development

### File Structure

```
browser-extension/
├── manifest.json       # Extension manifest
├── popup.html          # Popup UI
├── popup.js            # Popup logic
├── content.js          # Content script for corner badge
├── background.js       # Service worker
└── icons/
    ├── eye48.svg       # 48px icon
    └── eye128.svg      # 128px icon
```

### API Endpoints Used

- `POST https://api.akili.com.ng/api/v1/public/scan/website` - Website scanning

### Permissions Required

- `activeTab` - Access to current tab
- `storage` - Store API key and scan cache
- `notifications` - Show scan notifications
- `tabs` - Get tab information
- `https://api.akili.com.ng/*` - API access
- `<all_urls>` - Scan any website

## Security Notes

- API keys are stored locally in browser storage
- Scan results are cached for 1 hour
- No personal data is sent to external servers beyond the API
- The extension only scans publicly accessible information

## Support

For issues or questions:
- Visit `https://akili.com.ng/support`
- Check the AKILI documentation
- Review browser console for error messages
