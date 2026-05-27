chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'openPopup') {
    chrome.action.openPopup();
  }
});

// Clean up old cache entries on startup
chrome.runtime.onStartup.addListener(async () => {
  const cache = await chrome.storage.local.get('scanCache');
  if (cache.scanCache) {
    const now = Date.now();
    const oneHour = 3600000;
    
    for (const domain in cache.scanCache) {
      if (now - cache.scanCache[domain].timestamp > oneHour) {
        delete cache.scanCache[domain];
      }
    }
    
    await chrome.storage.local.set(cache);
  }
});
