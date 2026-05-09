# PipGuard Browser Extension

Real-time protection against malicious AI-generated Python packages for browser-based workflows.

## Features

### 🔍 Real-time Detection
- **AI Chat Integration**: Monitors ChatGPT, Claude, Gemini, and Copilot conversations
- **Clipboard Monitoring**: Intercepts copy-paste of package installation commands
- **Pattern Recognition**: Identifies suspicious package names and known malicious packages
- **Instant Alerts**: Shows warnings directly in AI chat interfaces

### 🛡️ Security Features
- **Malicious Package Database**: Syncs with OpenSSF and PyPA threat feeds
- **Typosquat Detection**: Identifies packages similar to popular libraries
- **Suspicious Pattern Matching**: Detects crypto miners, backdoors, keyloggers
- **Automatic Updates**: Keeps threat database current with latest advisories

### 🎯 User Experience
- **Non-intrusive**: Warnings appear inline without disrupting workflow
- **One-click Actions**: Install with PipGuard or block suspicious packages
- **Persistent Storage**: Remembers blocked packages and user preferences
- **Cross-platform**: Works on Chrome, Firefox, and Edge

## Installation

### Chrome/Edge
1. Download the extension files
2. Open `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the extension folder

### Firefox
1. Open `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on" and select the extension folder

## Usage

### AI Chat Integration
- Works automatically in ChatGPT, Claude, Gemini, and Copilot
- Shows warnings when suspicious packages are mentioned
- Provides one-click "Install with PipGuard" option

### Clipboard Protection
- Monitors clipboard for `pip install` commands
- Validates package names before installation
- Shows security alerts for suspicious packages

### Extension Popup
- View detected suspicious packages
- Manage blocked package list
- Clear warnings and check clipboard manually

## Security

### Data Sources
- OpenSSF Malicious Packages Database
- PyPA Advisory Database
- OSV.dev Vulnerability Database
- Community threat intelligence feeds

### Privacy
- All data stored locally in browser
- No personal data sent to external servers
- Optional telemetry can be disabled

## Development

### Building
```bash
# Package extension for distribution
zip -r pipguard-extension.zip *.js *.html *.json icons/
```

### Testing
```bash
# Load in development mode
# Chrome: chrome://extensions/ -> Developer mode -> Load unpacked
# Firefox: about:debugging -> Load Temporary Add-on
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request with security review

## License

MIT License - see LICENSE file for details
