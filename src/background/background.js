// Background service worker
console.log("Phishing Detector background service worker loaded.");

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Detector extension installed.");
});

// Import threat intelligence logic
importScripts('../utils/threat_intel.js');

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
    
    // Handle threat intelligence URL checking
    if (request.action === "check_threat_intel") {
        handleThreatIntelCheck(request, sendResponse);
        return true; // Keep message channel open for async response
    }
});

// Handle threat intelligence checking
async function handleThreatIntelCheck(request, sendResponse) {
    try {
        const { urls, apiKey } = request;
        
        if (!urls || urls.length === 0) {
            sendResponse({ verdict: 'unknown', urls: [] });
            return;
        }
        
        // Use the ThreatIntelligence class (loaded via importScripts)
        const threatIntel = new ThreatIntelligence();
        const result = await threatIntel.checkURLs(urls, apiKey);
        
        sendResponse(result);
    } catch (error) {
        console.error('Background: Threat intel error:', error);
        sendResponse({ 
            verdict: 'unknown', 
            error: error.message,
            urls: [] 
        });
    }
}
