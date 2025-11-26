/**
 * Phishing Detection Heuristics
 * 
 * This class contains rule-based logic to identify common phishing indicators.
 */
class HeuristicsEngine {
    constructor() {
        this.urgencyKeywords = [
            'urgent', 'immediate', 'suspend', 'ban', 'close', 'verify',
            'action required', 'unauthorized', 'locked', 'restricted'
        ];
    }

    /**
     * Analyze an email object and return a score and flags.
     * @param {Object} emailData - The extracted email data.
     * @param {string[]} allowlist - List of safe domains/emails.
     * @param {string[]} blocklist - List of blocked domains/emails.
     * @returns {Object} { score: number, flags: string[] }
     */
    analyze(emailData, allowlist = [], blocklist = []) {
        let score = 0;
        const flags = [];

        const senderEmail = emailData.senderEmail.toLowerCase();
        const senderDomain = senderEmail.split('@')[1];

        // 0. Check Verified Sender
        if (emailData.isVerified) {
            return { score: 0, flags: ['Verified Sender'], isSuspicious: false, isSkipped: true };
        }

        // 1. Check Allowlist/Blocklist
        if (allowlist.some(item => senderEmail.includes(item) || (senderDomain && senderDomain.includes(item)))) {
            return { score: 0, flags: ['Sender is in your Allowlist'], isSuspicious: false, isSkipped: true };
        }

        if (blocklist.some(item => senderEmail.includes(item) || (senderDomain && senderDomain.includes(item)))) {
            return { score: 100, flags: ['Sender is in your Blocklist'], isSuspicious: true };
        }

        // 1. Check for Sender Mismatch
        const mismatchScore = this.checkSenderMismatch(emailData.senderName, senderEmail);
        if (mismatchScore > 0) {
            score += mismatchScore;
            flags.push('Sender name mismatch (Possible impersonation)');
        }

        // 2. Check for Urgency
        let urgencyScore = 0;
        const hasSubjectUrgency = this.hasUrgency(emailData.subject);
        const hasBodyUrgency = this.hasUrgency(emailData.bodyText);

        if (hasSubjectUrgency) {
            urgencyScore += 20;
            flags.push('Urgent language in subject');
        }

        if (hasBodyUrgency) {
            urgencyScore += 20;
            flags.push('Urgent language in body');
        }

        // 3. Cap urgency score at 30 if both are present
        if (hasSubjectUrgency && hasBodyUrgency) {
            urgencyScore = 30;
        }

        score += urgencyScore;

        // 4. Check for Suspicious Links
        const linkAnalysis = this.analyzeLinks(emailData.links);
        if (linkAnalysis.hasIP) {
            score += 50;
            flags.push('Contains IP address link');
        }
        if (linkAnalysis.hasSuspiciousTLD) {
            score += 20;
            flags.push('Contains suspicious TLD');
        }

        // Cap score at 100
        score = Math.min(score, 100);

        return {
            score: score,
            flags: flags,
            isSuspicious: score > 40
        };
    }

    /**
     * Check text for urgency keywords.
     * @param {string} text 
     * @returns {boolean}
     */
    hasUrgency(text) {
        if (!text) return false;
        const lowerText = text.toLowerCase();
        return this.urgencyKeywords.some(keyword => lowerText.includes(keyword));
    }

    /**
     * Check if the sender name tries to impersonate a different email.
     * @param {string} name 
     * @param {string} email 
     * @returns {number} Score (0 or 50)
     */
    checkSenderMismatch(name, email) {
        if (!name || !email) return 0;

        // Extract potential email from name
        // Regex to find email-like strings in the name
        const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
        const matches = name.match(emailRegex);

        if (matches) {
            for (const match of matches) {
                // If the name contains an email that is NOT the actual sender email
                if (match.toLowerCase() !== email.toLowerCase()) {
                    return 50; // High suspicion
                }
            }
        }

        return 0;
    }

    /**
     * Analyze a list of links.
     * @param {string[]} links 
     * @returns {Object}
     */
    analyzeLinks(links) {
        let hasIP = false;
        let hasSuspiciousTLD = false;
        const suspiciousTLDs = ['.xyz', '.top', '.gq', '.tk', '.ml', '.cf'];

        if (!links) return { hasIP, hasSuspiciousTLD };

        links.forEach(link => {
            try {
                const url = new URL(link);

                // Check for IP address (basic regex)
                if (/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) {
                    hasIP = true;
                }

                // Check for suspicious TLDs
                if (suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
                    hasSuspiciousTLD = true;
                }
            } catch (e) {
                // Invalid URL, ignore
            }
        });

        return { hasIP, hasSuspiciousTLD };
    }
}

// Expose globally for content.js to use
window.PhishingHeuristics = new HeuristicsEngine();
