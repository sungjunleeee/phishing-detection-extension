// Content script for Gmail
console.log("Phishing Detector content script loaded on Gmail.");

// Simple observer to detect when email content might be loaded
// Gmail is a SPA, so we need to watch for DOM changes or URL changes
// This is a basic placeholder for the detection engine entry point

const observer = new MutationObserver((mutations) => {
    // In a real implementation, we would check for specific Gmail selectors
    // that indicate an open email view.
    // For now, we just log that activity is happening.
    // Debounce or limit this in production to avoid performance issues.
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Example function to extract text from the body (simplified)
function extractEmailContent() {
    // Gmail structure is complex, this is just a placeholder
    const emailBody = document.querySelector('.a3s.aiL'); // Common class for email body in Gmail
    if (emailBody) {
        console.log("Email content found:", emailBody.innerText.substring(0, 100) + "...");
        return emailBody.innerText;
    }
    return null;
}

// Listen for messages from popup or background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan_email") {
        const content = extractEmailContent();
        if (content) {
            sendResponse({ status: "scanned", result: "safe" }); // Mock result
        } else {
            sendResponse({ status: "error", message: "No email content found" });
        }
    }
});
