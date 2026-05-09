// PipGuard Browser Extension - Content Script
// Intercepts AI chat interfaces and validates package names in real-time

let maliciousPackages = new Set();
let lastClipboardContent = '';

// Initialize malicious package list
chrome.storage.local.get(['maliciousPackages'], (result) => {
  if (result.maliciousPackages) {
    maliciousPackages = new Set(result.maliciousPackages);
  }
});

// Listen for clipboard changes
document.addEventListener('copy', (e) => {
  const clipboardData = e.clipboardData || window.clipboardData;
  const text = clipboardData.getData('text');
  if (text && text !== lastClipboardContent) {
    lastClipboardContent = text;
    checkForMaliciousPackages(text);
  }
});

// Check for package names in text
function checkForMaliciousPackages(text) {
  const packageNames = extractPackageNames(text);
  const suspiciousPackages = packageNames.filter(pkg => 
    maliciousPackages.has(pkg.toLowerCase()) || 
    isSuspiciousPackageName(pkg)
  );
  
  if (suspiciousPackages.length > 0) {
    showWarning(suspiciousPackages);
  }
}

// Extract Python package names from text
function extractPackageNames(text) {
  const patterns = [
    /pip install\s+([a-zA-Z0-9._-]+)/g,
    /from\s+([a-zA-Z0-9._-]+)\s+import/g,
    /import\s+([a-zA-Z0-9._-]+)/g,
    /requirements:\s*([a-zA-Z0-9._-]+)/g
  ];
  
  const packages = new Set();
  patterns.forEach(pattern => {
    const matches = text.match(pattern);
    if (matches) {
      matches.slice(1).forEach(pkg => packages.add(pkg));
    }
  });
  
  return Array.from(packages);
}

// Check if package name looks suspicious
function isSuspiciousPackageName(packageName) {
  const suspiciousPatterns = [
    /^[a-z]*crypto[a-z]*$/i,
    /^[a-z]*miner[a-z]*$/i,
    /^[a-z]*hack[a-z]*$/i,
    /^[a-z]*crack[a-z]*$/i,
    /^[a-z]*steal[a-z]*$/i,
    /^[a-z]*keylog[a-z]*$/i,
    /^[a-z]*backdoor[a-z]*$/i,
    /^[a-z]*rat[a-z]*$/i
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(packageName));
}

// Show warning to user
function showWarning(suspiciousPackages) {
  const warningMessage = `
⚠️ PipGuard Security Alert ⚠️

Suspicious package(s) detected:
${suspiciousPackages.map(pkg => `• ${pkg}`).join('\n')}

These packages may be malicious or typosquats.
Consider using 'pipguard install ${suspiciousPackages[0]}' instead of 'pip install ${suspiciousPackages[0]}'.

[Dismiss] [Check with PipGuard]
  `.trim();
  
  // Show browser notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon48.png'),
    title: 'PipGuard Security Alert',
    message: `Suspicious packages detected: ${suspiciousPackages.join(', ')}`,
    priority: 2
  });
  
  // Store for potential popup
  chrome.storage.local.set({ 
    lastWarning: warningMessage,
    suspiciousPackages: suspiciousPackages,
    timestamp: Date.now()
  });
}

// Update malicious packages from storage
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateMaliciousPackages') {
    maliciousPackages = new Set(message.packages);
    chrome.storage.local.set({ maliciousPackages: Array.from(maliciousPackages) });
    sendResponse({ success: true });
  }
});

// Check current page for AI chat interfaces
function checkPageForAIInterface() {
  const aiDomains = [
    'chat.openai.com',
    'chatgpt.com',
    'claude.ai',
    'gemini.google.com',
    'copilot.github.com',
    'bard.google.com'
  ];
  
  const currentDomain = window.location.hostname;
  return aiDomains.includes(currentDomain);
}

// Inject warning styles into AI chat pages
function injectWarningStyles() {
  const style = document.createElement('style');
  style.textContent = `
    .pipguard-warning {
      background: #ff4444;
      color: white;
      padding: 12px;
      border-radius: 4px;
      margin: 10px 0;
      font-family: monospace;
      font-size: 14px;
      border-left: 4px solid #ff6666;
    }
    .pipguard-warning strong {
      color: #ff6666;
    }
    .pipguard-dismiss {
      background: #666;
      color: white;
      border: none;
      padding: 4px 8px;
      border-radius: 2px;
      cursor: pointer;
      margin-left: 10px;
    }
    .pipguard-dismiss:hover {
      background: #888;
    }
  `;
  document.head.appendChild(style);
}

// Show warning on AI chat pages
function showAIPageWarning(suspiciousPackages) {
  injectWarningStyles();
  
  const warningDiv = document.createElement('div');
  warningDiv.className = 'pipguard-warning';
  warningDiv.innerHTML = `
    <strong>⚠️ PipGuard Security Alert</strong>
    Suspicious packages detected in your conversation: ${suspiciousPackages.join(', ')}
    <button class="pipguard-dismiss" onclick="this.parentElement.remove()">Dismiss</button>
  `;
  
  // Insert at top of page
  const targetElement = document.querySelector('body');
  if (targetElement) {
    targetElement.insertBefore(warningDiv, targetElement.firstChild);
  }
}

// Initialize on page load
if (checkPageForAIInterface()) {
  // Monitor for package mentions in chat
  const observer = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const text = node.textContent || '';
          const packages = extractPackageNames(text);
          if (packages.length > 0) {
            const suspiciousPackages = packages.filter(pkg => 
              maliciousPackages.has(pkg.toLowerCase()) || 
              isSuspiciousPackageName(pkg)
            );
            if (suspiciousPackages.length > 0) {
              showAIPageWarning(suspiciousPackages);
            }
          }
        }
      });
    });
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}
