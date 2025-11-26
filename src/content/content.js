// Content script for Gmail
console.log("Phishing Detector content script loaded on Gmail.");

// Selectors for Gmail elements (subject to change by Google)
const SELECTORS = {
    senderName: 'span.gD', // Sender Name
    senderEmail: 'span.go', // Sender Email (< email >)
    subject: 'h2.hP', // Subject Line
    body: 'div.a3s.aiL', // Email Body container
    replyBody: 'div.gmail_quote', // Quoted text (to exclude if needed)
    recipientDetails: 'div.ajy' // Container for To/Cc details (often hidden)
};

function extractEmailData() {
    const senderNameNode = document.querySelector(SELECTORS.senderName);
    const senderEmailNode = document.querySelector(SELECTORS.senderEmail);
    const subjectNode = document.querySelector(SELECTORS.subject);
    const bodyNode = document.querySelector(SELECTORS.body);

    if (!bodyNode) {
        console.log("Phishing Detector: No email body found. User might be in inbox view.");
        return null;
    }

    // Robust Sender Email Extraction
    let senderEmail = "Unknown";
    if (senderEmailNode) {
        senderEmail = senderEmailNode.innerText.replace(/[<>]/g, '');
    } else if (senderNameNode && senderNameNode.getAttribute('email')) {
        // Fallback: Gmail often stores the email in the 'email' attribute of the name node
        senderEmail = senderNameNode.getAttribute('email');
    }

    // Attempt to extract To/Cc
    // Strategy 1: Standard "to me" section
    const recipientNode = document.querySelector('.g2');
    let recipients = "Unknown";

    if (recipientNode) {
        recipients = recipientNode.innerText;
        const emailNodes = recipientNode.querySelectorAll('[email]');
        if (emailNodes.length > 0) {
            const emailList = Array.from(emailNodes).map(node => node.getAttribute('email'));
            recipients += ` (${emailList.join(', ')})`;
        }
    }

    // Strategy 2: User-provided selector (likely for expanded details or specific view)
    // #avWBGd-1 > ... > div.iw.ajw > span > span
    // We generalize this to avoid the specific ID at the start
    if (recipients === "Unknown" || recipients === "me" || !recipients.includes('@')) {
        const specificNode = document.querySelector('div.iw.ajw > span > span');
        if (specificNode) {
            recipients = specificNode.innerText;
            // Check if there's an email attribute here too
            if (specificNode.getAttribute('email')) {
                recipients += ` (${specificNode.getAttribute('email')})`;
            }
        }
    }

    // Strategy 3: Check title attribute of the recipient node (common in Gmail for tooltips)
    if (!recipients.includes('@') && recipientNode) {
        const title = recipientNode.getAttribute('title');
        if (title && title.includes('@')) {
            recipients += ` (${title})`;
        }
    }

    const data = {
        senderName: senderNameNode ? senderNameNode.innerText : "Unknown",
        senderEmail: senderEmail,
        recipients: recipients, // New field
        subject: subjectNode ? subjectNode.innerText : "No Subject",
        bodyText: bodyNode.innerText,
        links: Array.from(bodyNode.querySelectorAll('a')).map(a => a.href),
        timestamp: new Date().toISOString()
    };

    console.log("Phishing Detector: Extracted Data", data);
    return data;
}

// Cache for the last analysis result
let cachedResult = null;
let cachedUrl = "";

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_cache") {
        if (cachedResult && cachedUrl === location.href) {
            sendResponse(cachedResult);
        } else {
            sendResponse(null);
        }
        return true;
    }

    if (request.action === "scan_email") {
        // Check cache first
        if (cachedResult && cachedUrl === location.href) {
            console.log("Phishing Detector: Returning cached result");
            sendResponse(cachedResult);
            return true;
        }

        const emailData = extractEmailData();

        if (emailData) {
            const analysisResult = runAnalysis(emailData);

            // Update badge after manual scan
            updateBadge(analysisResult);

            let resultStatus = analysisResult.isSuspicious ? "suspicious" : "safe";
            if (analysisResult.isSkipped) resultStatus = "skipped";

            const response = {
                status: "scanned",
                data: emailData,
                result: resultStatus,
                analysis: analysisResult
            };

            // Cache the result
            cachedResult = response;
            cachedUrl = location.href;

            sendResponse(response);
        } else {
            sendResponse({
                status: "error",
                message: "No email open or content not found."
            });
        }
    }
    return true; // Keep message channel open for async response
});

// Settings
let settings = {
    autoscan: false,
    allowlist: ['columbia.edu'],
    blocklist: []
};

// Load settings
chrome.storage.sync.get(['autoscan', 'allowlist', 'blocklist'], (result) => {
    settings = { ...settings, ...result };
    console.log("Phishing Detector: Settings loaded", settings);
});

// Listen for settings changes
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'sync') {
        if (changes.autoscan) settings.autoscan = changes.autoscan.newValue;
        if (changes.allowlist) settings.allowlist = changes.allowlist.newValue;
        if (changes.blocklist) settings.blocklist = changes.blocklist.newValue;
    }
});

// Helper to run analysis
function runAnalysis(emailData) {
    let analysisResult = { score: 0, flags: [], isSuspicious: false };

    if (window.PhishingHeuristics) {
        analysisResult = window.PhishingHeuristics.analyze(emailData, settings.allowlist, settings.blocklist);
        console.log("Phishing Detector: Analysis Result", analysisResult);
    } else {
        console.error("Phishing Detector: Heuristics engine not loaded.");
    }
    return analysisResult;
}

// Auto-scan observer
let lastUrl = location.href;
const observer = new MutationObserver(() => {
    // Check if URL changed
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        // Clear cache on navigation
        cachedResult = null;
        cachedUrl = "";
        handleEmailDetection();
    }

    // Also check if an email body appeared
    if (document.querySelector(SELECTORS.body)) {
        handleEmailDetection();
    }
});

observer.observe(document.body, { subtree: true, childList: true });

let detectionDebounce = null;
function handleEmailDetection() {
    if (detectionDebounce) clearTimeout(detectionDebounce);
    detectionDebounce = setTimeout(() => {
        if (settings.autoscan) {
            attemptAutoScan();
        } else {
            checkForEmailPresence();
        }
    }, 200);
}

function attemptAutoScan() {
    const emailData = extractEmailData();
    if (emailData) {
        const result = runAnalysis(emailData);
        updateBadge(result);

        // Cache result
        cachedResult = {
            status: "scanned",
            data: emailData,
            result: result.isSuspicious ? "suspicious" : "safe",
            analysis: result
        };
        cachedUrl = location.href;
    } else {
        chrome.runtime.sendMessage({ action: "update_badge", text: "" });
    }
}

function checkForEmailPresence() {
    // Check if we already have a result for this email
    if (cachedResult && cachedUrl === location.href) {
        return;
    }

    // We only check if the BODY element exists, we don't extract data yet
    const bodyNode = document.querySelector(SELECTORS.body);
    if (bodyNode) {
        // Email detected! Set badge to "scan" (Yellow)
        chrome.runtime.sendMessage({
            action: "update_badge",
            text: "Scan",
            color: "#FBC02D" // Yellow
        });
    } else {
        // Clear badge if no email found
        chrome.runtime.sendMessage({ action: "update_badge", text: "" });
    }
}

function updateBadge(result) {
    if (result.isSkipped) {
        chrome.runtime.sendMessage({
            action: "update_badge",
            text: "Skip",
            color: "#9E9E9E" // Grey
        });
    } else if (result.isSuspicious) {
        chrome.runtime.sendMessage({
            action: "update_badge",
            text: "!",
            color: "#D32F2F" // Red
        });
    } else {
        chrome.runtime.sendMessage({
            action: "update_badge",
            text: "Safe",
            color: "#388E3C" // Green
        });
    }
}
