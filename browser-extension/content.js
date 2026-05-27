function getGradeColor(grade) {
  const gradeUpper = (grade || 'F').toUpperCase();
  if (gradeUpper === 'A' || gradeUpper === 'B') return '#10B981';
  if (gradeUpper === 'C') return '#F59E0B';
  return '#EF4444';
}

function injectResultBadge(grade, score) {
  // Remove existing badge if present
  const existingBadge = document.getElementById('akili-badge');
  if (existingBadge) {
    existingBadge.remove();
  }
  
  const badge = document.createElement('div');
  badge.id = 'akili-badge';
  badge.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: ${getGradeColor(grade)};
    color: white;
    font-family: sans-serif;
    font-weight: bold;
    font-size: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 999999;
    cursor: pointer;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    transition: transform 0.2s;
  `;
  badge.textContent = (grade || 'F').toUpperCase();
  badge.title = `AKILI Score: ${score}/100`;
  badge.onclick = () => {
    chrome.runtime.sendMessage({action: 'openPopup'});
  };
  
  document.body.appendChild(badge);
  
  // Auto-hide after 5 seconds
  setTimeout(() => {
    badge.style.opacity = '0';
    badge.style.transition = 'opacity 0.5s';
    setTimeout(() => badge.remove(), 500);
  }, 5000);
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showBadge') {
    injectResultBadge(request.grade, request.score);
  }
});
