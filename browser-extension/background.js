// PipGuard Browser Extension - Background Script
// Manages malicious package database and communicates with content scripts

// Initialize malicious package database
let maliciousPackages = new Set();

// Load initial malicious packages
const initialMaliciousPackages = [
  'reqeusts', 'urlib3', 'fake-crypto', 'pytorch-lightning',
  'chat-gpt-api', 'openai-gpt', 'crypto-miner-tool',
  'backdoor-utils', 'keylogger-pro', 'data-stealer'
];

maliciousPackages.forEach(pkg => maliciousPackages.add(pkg));

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkPackages') {
    const packages = message.packages.map(pkg => pkg.toLowerCase());
    const suspiciousPackages = packages.filter(pkg => 
      maliciousPackages.has(pkg) || isSuspiciousPackageName(pkg)
    );
    
    sendResponse({
      suspiciousPackages: suspiciousPackages,
      allMalicious: Array.from(maliciousPackages)
    });
  }
  
  if (message.action === 'updateMaliciousPackages') {
    message.packages.forEach(pkg => maliciousPackages.add(pkg.toLowerCase()));
    chrome.storage.local.set({ maliciousPackages: Array.from(maliciousPackages) });
    sendResponse({ success: true });
  }
  
  if (message.action === 'getMaliciousPackages') {
    sendResponse({ maliciousPackages: Array.from(maliciousPackages) });
  }
});

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

// Update malicious packages from external sources
async function updateMaliciousPackages() {
  try {
    // Fetch from OpenSSF malicious packages
    const response = await fetch('https://api.github.com/repos/ossf/malicious-packages/contents/py');
    if (response.ok) {
      const data = await response.json();
      
      for (const file of data) {
        if (file.name.endsWith('.json')) {
          const fileResponse = await fetch(file.download_url);
          if (fileResponse.ok) {
            const content = await fileResponse.json();
            const maliciousData = JSON.parse(atob(content.content));
            
            maliciousData.forEach(pkg => {
              maliciousPackages.add(pkg.name.toLowerCase());
            });
          }
        }
      }
    }
    
    // Save to storage
    chrome.storage.local.set({ maliciousPackages: Array.from(maliciousPackages) });
    console.log('Updated malicious packages database');
  } catch (error) {
    console.error('Failed to update malicious packages:', error);
  }
}

// Initialize on extension startup
chrome.runtime.onInstalled.addListener(() => {
  // Load stored packages
  chrome.storage.local.get(['maliciousPackages'], (result) => {
    if (result.maliciousPackages) {
      maliciousPackages = new Set(result.maliciousPackages);
    }
  });
  
  // Update database
  updateMaliciousPackages();
  
  // Schedule regular updates
  setInterval(updateMaliciousPackages, 24 * 60 * 60 * 1000); // Every 24 hours
});
