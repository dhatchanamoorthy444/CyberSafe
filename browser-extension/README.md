# CyberSafe Browser Extension

## Overview

The CyberSafe browser extension brings offline URL security analysis directly to your browser. Right-click any link to analyze it with CyberSafe's risk engine—without visiting the destination.

## Features

- **Context Menu Integration**: Right-click any link and select "Analyze with CyberSafe"
- **Current Tab Analysis**: Analyze the URL of your current browser tab
- **Keyboard Shortcut**: Press `Ctrl+Shift+Y` (Windows/Linux) or `Cmd+Shift+Y` (Mac) to open the analyzer
- **Instant Results**: See verdict, risk score, and detection rules in a compact popup
- **Safe Analysis**: The extension never visits the destination—only analyzes the URL structure

## Installation

### For Development

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in the top right)
3. Click "Load unpacked"
4. Select the `browser-extension` directory from the CyberSafe project

### For Production

*Coming soon: CyberSafe will be available on the Chrome Web Store*

## How to Use

### Method 1: Context Menu
1. Right-click any link on a web page
2. Select "Analyze with CyberSafe" from the context menu
3. View the analysis results in the popup

### Method 2: Manual Entry
1. Click the CyberSafe extension icon in your browser toolbar
2. Paste or type a URL in the input field
3. Click "Analyze"

### Method 3: Current Tab
1. Open the extension popup
2. Click "Current Tab" to analyze the URL of the active tab

### Method 4: Keyboard Shortcut
1. Press `Ctrl+Shift+Y` (Windows/Linux) or `Cmd+Shift+Y` (Mac)
2. The extension popup opens automatically

## Understanding Results

### Verdict

- **SAFE**: No structural red flags detected (score 0-19)
- **REVIEW**: Some indicators present—verify before proceeding (score 20-49)
- **SUSPICIOUS**: Multiple red flags—do not proceed (score 50+)

### Findings

Each finding shows:
- **Title**: The detection rule that triggered
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **Message**: Why this pattern is concerning

### View Full Analysis

Click "Open Full Analysis" in the footer to see the complete breakdown on the CyberSafe web app, including:
- URL anatomy visualization
- Risk score breakdown
- Explainable findings with WHAT/WHY/ACTION
- IOC extraction
- Security recommendations

## Privacy & Security

- **No destination requests**: CyberSafe never visits the URL you're analyzing
- **No tracking**: The extension does not collect or store your browsing history
- **Offline analysis**: URLs are analyzed by structure only
- **Secure API**: Analysis requests go directly to the CyberSafe backend over HTTPS

## Permissions Explained

- **activeTab**: Allows the extension to read the URL of the current tab when you click "Current Tab"
- **contextMenus**: Adds the "Analyze with CyberSafe" option to the right-click menu
- **host_permissions (cybersafe01.vercel.app)**: Required to send URLs to the CyberSafe API for analysis

## Troubleshooting

### Extension popup doesn't open
- Check that the extension is enabled in `chrome://extensions/`
- Try reloading the extension (click the refresh icon)

### Analysis fails or times out
- The CyberSafe backend may be starting up (Vercel free tier cold start)
- Wait 30 seconds and try again
- Check your internet connection

### "Could not access current tab URL"
- Some browser pages (chrome://, edge://, about:) cannot be accessed by extensions
- Try the extension on a regular web page

## Keyboard Shortcuts

You can customize the keyboard shortcut:
1. Go to `chrome://extensions/shortcuts`
2. Find "CyberSafe Link Analyzer"
3. Click the pencil icon next to "Analyze current tab"
4. Enter your preferred shortcut

## Support

- **Report Issues**: [GitHub Issues](https://github.com/yourusername/cybersafe/issues)
- **API Docs**: https://cybersafebackend.onrender.com/docs
- **Web App**: https://cybersafe01.vercel.app

## Version

**v2.0.0** — Initial release with offline URL analysis engine

## License

Copyright © 2026 CyberSafe. All rights reserved.
