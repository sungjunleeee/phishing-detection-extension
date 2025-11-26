// Background service worker
console.log("Phishing Detector background service worker loaded.");

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Detector extension installed.");
});
