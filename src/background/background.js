// Background service worker
console.log("Phishing Detector background service worker loaded.");

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Detector extension installed.");
});

// Listen for messages from content script to update badge
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "update_badge") {
        const tabId = sender.tab ? sender.tab.id : null;
        if (tabId) {
            // Set badge text
            chrome.action.setBadgeText({
                text: request.text,
                tabId: tabId
            });

            // Set badge color
            if (request.color) {
                chrome.action.setBadgeBackgroundColor({
                    color: request.color,
                    tabId: tabId
                });
            }
        }
    }
});
