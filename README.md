# 🦁 Phishing & Deepfake Detection for Gmail

A privacy-first Chrome extension designed to protect Columbia University students (and everyone else!) from phishing attacks and deepfake content in Gmail.

## ✨ Key Features

*   **🔒 Privacy-First**: All analysis happens **locally** on your browser. No email data is ever sent to external servers.
*   **🧠 Heuristic Analysis**: Detects common phishing indicators:
    *   **Urgency Detection**: Flags suspicious urgent language (e.g., "Immediate Action Required").
    *   **Link Analysis**: Identifies suspicious links (IP addresses, dangerous TLDs like .xyz, .top).
*   **⚙️ Customizable Settings**:
    *   **Allowlist**: Mark trusted domains (e.g., `columbia.edu`) to skip scanning.
    *   **Blocklist**: Always flag specific suspicious senders.
    *   **Auto-Scan**: Optional feature to scan emails automatically upon opening.
*   **🦁 Custom Icons**: Features the Columbia Lion!

## 🚀 Installation

1.  Clone or download this repository.
2.  Open Chrome and navigate to `chrome://extensions`.
3.  Enable **"Developer mode"** in the top right corner.
4.  Click **"Load unpacked"**.
5.  Select the `phishing-detection-extension` directory.

## 📖 Usage

### Default Mode (Privacy-Focused)
1.  Open an email in Gmail.
2.  The extension icon will show a **Yellow "Scan"** badge.
3.  **Click the extension icon** and hit the **"Scan"** button.
4.  The badge will update to:
    *   **Green (Safe)**: No issues found.
    *   **Red (!)**: Suspicious content detected.
    *   **Grey (Skip)**: Sender is in your Allowlist.

### Settings & Configuration
Right-click the extension icon and select **"Options"** to access the Settings Page:

*   **Enable Auto-Scan**: Toggle this to have the extension automatically scan every email you open (no click required).
*   **Allowlist**: Add safe domains (e.g., `columbia.edu`) to ignore warnings.
*   **Blocklist**: Add known spam domains to always flag them.

## 🛠️ Development Structure

```text
phishing-detection-extension/
├── manifest.json        # Extension configuration
├── src/                 # Source code
│   ├── background/      # Background service workers
│   │   └── background.js
│   ├── content/         # Scripts injected into web pages
│   │   └── content.js
│   ├── options/         # Settings page implementation
│   │   ├── options.html
│   │   ├── options.js
│   │   └── options.css
│   ├── popup/           # Extension popup implementation
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   └── utils/           # Shared utilities and logic
│       └── heuristics.js
└── assets/              # Static assets (images, fonts)
    └── icons/           # Extension icons
```

## 🔒 Privacy Policy

This extension is strictly scoped to `mail.google.com`. It does not collect, store, or transmit your personal data. All analysis is performed client-side using JavaScript.
