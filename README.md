# Phishing & Deepfake Detection Extension

A Chrome extension for detecting phishing and deepfake content in Gmail.

## Project Structure

- `manifest.json`: Extension configuration (Manifest V3).
- `background.js`: Service worker.
- `content.js`: Script that runs on Gmail to analyze content.
- `popup/`: Extension popup UI.
- `utils/`: Shared utilities (heuristic rules, etc.).

## Setup Instructions

1.  Open Chrome and navigate to `chrome://extensions`.
2.  Enable "Developer mode" in the top right corner.
3.  Click "Load unpacked".
4.  Select the `phishing-detection-extension` directory.

## Usage

1.  Open Gmail (`mail.google.com`).
2.  Open an email.
3.  Click the extension icon in the toolbar.
4.  Click "Scan Current Email".

## Development

- **Popup**: Modify `popup/popup.html`, `popup/popup.css`, `popup/popup.js`.
- **Logic**: Add detection logic to `content.js` or `utils/`.
