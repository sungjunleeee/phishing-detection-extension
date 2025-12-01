// Content script for Gmail
console.log("Phishing Detector content script loaded on Gmail.");

// Selectors for Gmail elements (subject to change by Google)
const SELECTORS = {
    senderName: 'span.gD', // Sender Name
    senderEmail: 'span.go', // Sender Email (< email >)
    subject: 'h2.hP', // Subject Line
    body: 'div.a3s.aiL', // Email Body container
    replyBody: 'div.gmail_quote', // Quoted text (to exclude if needed)
    recipientDetails: 'div.ajy', // Container for To/Cc details (often hidden)
    verifiedIcon: 'span.bce[alt="Verified Sender"]' // Verified Sender Icon
};

function extractEmailData() {
    const senderNameNode = document.querySelector(SELECTORS.senderName);
    const senderEmailNode = document.querySelector(SELECTORS.senderEmail);
    const subjectNode = document.querySelector(SELECTORS.subject);
    const bodyNode = document.querySelector(SELECTORS.body);
    const verifiedNode = document.querySelector(SELECTORS.verifiedIcon);

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
        recipients: recipients,
        subject: subjectNode ? subjectNode.innerText : "No Subject",
        bodyText: bodyNode.innerText,
        links: Array.from(bodyNode.querySelectorAll('a')).map(a => a.href),
        isVerified: !!verifiedNode, // True if verified icon exists
        timestamp: new Date().toISOString()
    };

    // Extract Encryption Status (TLS/S/MIME)
    // We look for the security details in the expanded details pane (div.ajA.SK)
    // Since the ID is dynamic, we search for the container class
    const detailsContainer = document.querySelector('div.ajA.SK');
    if (detailsContainer) {
        // Look for the security row. It usually contains a lock icon or text like "Standard encryption"
        // The user pointed to a specific table row, but we'll try to find the text to be robust
        const rows = Array.from(detailsContainer.querySelectorAll('tr'));
        // Use textContent instead of innerText to ensure we can read it even if hidden/styled out of flow
        const securityRow = rows.find(row => row.textContent.includes('encryption') || row.textContent.includes('security') || row.textContent.includes('TLS') || row.textContent.includes('S/MIME'));

        if (securityRow) {
            data.encryptionStatus = securityRow.textContent;
        } else {
            // Fallback: Try the user's specific path if generic search fails, but generalize the ID
            const specificNode = document.querySelector('div.adn.ads div.ajA.SK table tr:nth-child(7) td.gL span span');
            if (specificNode) {
                data.encryptionStatus = specificNode.textContent;
            }
        }
    }

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
        handleScanRequest(sendResponse);
        return true; // Keep message channel open for async response
    }
    return true;
});

async function handleScanRequest(sendResponse) {
    // Check cache first
    if (cachedResult && cachedUrl === location.href) {
        console.log("Phishing Detector: Returning cached result");
        sendResponse(cachedResult);
        return;
    }

    // Enable hidden mode to prevent flash
    setHiddenMode(true);

    // Attempt to expand details if not visible
    const wasExpanded = await expandDetails();

    // Allow a brief moment for DOM to update after expansion
    await new Promise(resolve => setTimeout(resolve, 50));

    const emailData = extractEmailData();

    // Restore state if we expanded it
    if (wasExpanded) {
        collapseDetails();
    }

    // Disable hidden mode
    setHiddenMode(false);

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

// Helper to toggle details
async function expandDetails() {
    const detailsPane = document.querySelector('div.ajA.SK');
    if (detailsPane) return false; // Already open

    // Try to find the toggle button
    // Strategy: Look for the arrow icon or the button with aria-label "Show details"
    const toggleBtn = document.querySelector('span[aria-label="Show details"]') ||
        document.querySelector('img.ajz');

    if (toggleBtn) {
        toggleBtn.click();
        return true; // We opened it
    }
    return false;
}

function collapseDetails() {
    const toggleBtn = document.querySelector('span[aria-label="Hide details"]') ||
        document.querySelector('img.ajz');
    if (toggleBtn) {
        toggleBtn.click();
    }
}

function setHiddenMode(enabled) {
    const styleId = 'phishing-detector-hide-details';
    let style = document.getElementById(styleId);
    if (enabled) {
        if (!style) {
            style = document.createElement('style');
            style.id = styleId;
            // Hide the details pane and take it out of flow to prevent jump
            style.textContent = `
                div.ajA.SK {
                    opacity: 0 !important;
                    position: absolute !important;
                    pointer-events: none !important;
                    z-index: -9999 !important;
                }
            `;
            document.head.appendChild(style);
        }
    } else {
        if (style) {
            style.remove();
        }
    }
}

// Settings
let settings = {
    autoscan: false,
    allowlist: ['columbia.edu'],
    blocklist: []
};

// Load settings
chrome.storage.sync.get(['autoscan', 'allowlist', 'blocklist', 'threatIntel_enabled', 'api_virustotal'], (result) => {
    settings = { ...settings, ...result };
    console.log("Phishing Detector: Settings loaded", settings);
});

// Listen for settings changes
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'sync') {
        if (changes.autoscan) settings.autoscan = changes.autoscan.newValue;
        if (changes.allowlist) settings.allowlist = changes.allowlist.newValue;
        if (changes.blocklist) settings.blocklist = changes.blocklist.newValue;
        if (changes.threatIntel_enabled) settings.threatIntel_enabled = changes.threatIntel_enabled.newValue;
        if (changes.api_virustotal) settings.api_virustotal = changes.api_virustotal.newValue;
    }
});

async function runAnalysis(emailData) {
    // 1. NEW: Threat Intelligence Check (VirusTotal)
    const urls = emailData.links || [];
    if (urls.length > 0 && settings.threatIntel_enabled && settings.api_virustotal) {
        try {
            console.log('Phishing Detector: Checking URLs with VirusTotal...');
            const threatResult = await window.ThreatIntel.checkURLs(
                urls, 
                settings.api_virustotal
            );
            
            // If malicious URL, flag immediately
            if (threatResult.verdict === 'malicious') {
                const maliciousUrl = threatResult.urls[0];
                
                return {
                    score: 100,
                    isSuspicious: true,
                    isSkipped: false,
                    flags: [
                        `Malicious URL detected by ${maliciousUrl.malicious}/${maliciousUrl.totalScanners} security vendors`,
                        `  → ${maliciousUrl.url}`
                    ],
                    threatIntel: threatResult,
                    explanation: {
                        verdict: 'This email contains a malicious link',
                        reasons: [{
                            category: 'Threat Intelligence',
                            description: `Flagged by ${maliciousUrl.malicious} security vendors on VirusTotal`,
                            detail: maliciousUrl.reportUrl
                        }]
                    }
                };
            }
            
            // If suspicious URL, log URL (to be used in combined analysis la)
            if (threatResult.verdict === 'suspicious') {
                console.log('Phishing Detector: URL flagged as suspicious by VirusTotal');
            }
        } catch (error) {
            console.error('Phishing Detector: Threat intelligence check failed:', error);
            // Continue with normal analysis on error
        }
    }

    // 2. Run existing heuristics
    let heuristicResult = { score: 0, flags: [], isSuspicious: false };

    if (window.PhishingHeuristics) {
        heuristicResult = window.PhishingHeuristics.analyze(
            emailData,
            settings.allowlist,
            settings.blocklist
        );
        console.log("Phishing Detector: Heuristic Analysis Result", heuristicResult);
    } else {
        console.error("Phishing Detector: Heuristics engine not loaded.");
    }

    // If heuristics decided we should skip (verified sender / allowlist), bail out early
    if (heuristicResult.isSkipped) {
        // Generate explanation for skipped emails
        if (window.ExplanationGenerator) {
            const explanation = window.ExplanationGenerator.generateExplanation(emailData, heuristicResult);
            heuristicResult.explanation = explanation;
        }
        return heuristicResult;
    }

    // 3. Naive Bayes analysis on subject + body
    let bayes = null;
    let phishingProbability = null;
    let legitProbability = null;

    if (window.NaiveBayesEmailClassifier && typeof window.NaiveBayesEmailClassifier.predict === "function") {
        const fullText = `${emailData.subject || ""}\n\n${emailData.bodyText || ""}`;
        bayes = window.NaiveBayesEmailClassifier.predict(fullText);

        phishingProbability = bayes.phishingProbability;
        legitProbability = bayes.legitProbability;

        // Calculate ML contribution to score
        // We only add to the score if probability > 0.5
        // 0.5 -> 0 pts
        // 0.8 -> 60 pts
        // 1.0 -> 100 pts
        const mlScore = Math.max(0, (phishingProbability - 0.5) * 200);

        // Add to heuristic score and cap at 100
        heuristicResult.score = Math.min(100, Math.round(heuristicResult.score + mlScore));

        // 4. Combine: upgrade to suspicious if Bayes thinks it's strongly phishing
        const combinedSuspicious =
            heuristicResult.isSuspicious ||
            phishingProbability >= 0.8 ||                        // very likely phishing
            (phishingProbability >= 0.6 && heuristicResult.score >= 40); // both mildly bad

        heuristicResult.isSuspicious = combinedSuspicious;
    } else {
        console.warn("Phishing Detector: NaiveBayesEmailClassifier not available");
    }

    // 5. Return combined result, preserving old fields but adding Bayes info
    const result = {
        ...heuristicResult,
        bayes,
        phishingProbability,
        legitProbability
    };

    // 6. Generate human-readable explanation
    if (window.ExplanationGenerator) {
        const explanation = window.ExplanationGenerator.generateExplanation(emailData, result);
        result.explanation = explanation;
    }

    return result;
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

async function attemptAutoScan() {
    // Enable hidden mode to prevent flash/layout shift
    setHiddenMode(true);

    // Attempt to expand details if not visible to capture encryption status
    const wasExpanded = await expandDetails();

    // Allow a brief moment for DOM to update after expansion
    await new Promise(resolve => setTimeout(resolve, 50));

    const emailData = extractEmailData();

    // Restore state if we expanded it
    if (wasExpanded) {
        collapseDetails();
    }

    // Disable hidden mode
    setHiddenMode(false);

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
