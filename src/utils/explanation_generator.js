/**
 * Explanation Generator
 *
 * Generates human-readable explanations for why an email was flagged as suspicious.
 * Provides specific evidence from the email to help users understand the verdict.
 */

class ExplanationGenerator {
    /**
     * Generate a clear explanation based on analysis results
     * @param {Object} emailData - The email data
     * @param {Object} analysisResult - The analysis result with flags and scores
     * @returns {Object} { summary: string, details: string[], evidence: Object[] }
     */
    generateExplanation(emailData, analysisResult) {
        if (analysisResult.isSkipped) {
            return this.generateSkippedExplanation(analysisResult);
        }

        if (!analysisResult.isSuspicious) {
            return this.generateSafeExplanation(emailData, analysisResult);
        }

        return this.generateSuspiciousExplanation(emailData, analysisResult);
    }

    /**
     * Generate explanation for skipped emails
     */
    generateSkippedExplanation(analysisResult) {
        const flag = analysisResult.flags[0] || '';

        if (flag.includes('Verified Sender')) {
            return {
                summary: "This email is from a verified sender and was not scanned.",
                details: ["Gmail has verified this sender's identity."],
                evidence: []
            };
        }

        if (flag.includes('Allowlist')) {
            return {
                summary: "This sender is on your trusted list and was not scanned.",
                details: ["You've marked this domain as safe in your settings."],
                evidence: []
            };
        }

        return {
            summary: "This email was skipped.",
            details: [],
            evidence: []
        };
    }

    /**
     * Generate explanation for safe emails
     */
    generateSafeExplanation(emailData, analysisResult) {
        const reasons = [];

        // Check what made it safe
        if (!analysisResult.flags || analysisResult.flags.length === 0) {
            reasons.push("No suspicious indicators were found.");
        }

        const score = analysisResult.score || 0;
        if (score < 20) {
            reasons.push("The email appears normal with no red flags.");
        } else if (score < 40) {
            reasons.push("Only minor concerns were detected, not enough to flag as suspicious.");
        }

        // If ML was involved
        if (analysisResult.phishingProbability !== null && analysisResult.phishingProbability < 0.5) {
            reasons.push("The content and language appear legitimate.");
        }

        return {
            summary: "This email appears safe.",
            details: reasons,
            evidence: []
        };
    }

    /**
     * Generate explanation for suspicious emails
     */
    generateSuspiciousExplanation(emailData, analysisResult) {
        const evidence = [];
        const issueTypes = [];

        // Analyze flags to build explanation
        const flags = analysisResult.flags || [];

        // Track detected issues
        let hasSenderMismatch = false;
        let hasBlocklist = false;
        let hasNoEncryption = false;
        let hasUrgency = false;
        let hasSuspiciousLinks = false;
        let hasHighMLConfidence = false;

        // 1. Sender mismatch (highest priority - clear phishing indicator)
        const senderMismatch = flags.find(f => f.includes('Sender name mismatch') || f.includes('impersonation'));
        if (senderMismatch) {
            hasSenderMismatch = true;
            issueTypes.push('sender impersonation');
            evidence.push({
                type: 'sender',
                label: 'Suspicious sender',
                value: `"${emailData.senderName}" <${emailData.senderEmail}>`
            });
        }

        // 2. Blocklist
        const blocklisted = flags.find(f => f.includes('Blocklist'));
        if (blocklisted) {
            hasBlocklist = true;
            issueTypes.push('blocked sender');
            evidence.push({
                type: 'sender',
                label: 'Blocked sender',
                value: emailData.senderEmail
            });
        }

        // 3. No encryption
        const noEncryption = flags.find(f => f.includes('not encrypted'));
        if (noEncryption) {
            hasNoEncryption = true;
            issueTypes.push('missing encryption');
            evidence.push({
                type: 'security',
                label: 'No encryption',
                value: 'Missing TLS/S/MIME'
            });
        }

        // 4. Urgency tactics
        const urgencySubject = flags.find(f => f.includes('Urgent language in subject'));
        const urgencyBody = flags.find(f => f.includes('Urgent language in body'));

        if (urgencySubject || urgencyBody) {
            hasUrgency = true;
            issueTypes.push('pressure tactics');
            const urgencyExplanation = this.explainUrgency(emailData, urgencySubject, urgencyBody);
            if (urgencyExplanation.examples.length > 0) {
                evidence.push({
                    type: 'urgency',
                    label: 'Pressure tactics',
                    value: urgencyExplanation.examples.join(', ')
                });
            }
        }

        // 5. Suspicious links
        const ipLink = flags.find(f => f.includes('IP address link'));
        const suspiciousTLD = flags.find(f => f.includes('suspicious TLD'));

        if (ipLink || suspiciousTLD) {
            hasSuspiciousLinks = true;
            if (ipLink) {
                issueTypes.push('IP address links');
            } else {
                issueTypes.push('suspicious domains');
            }
            const linkExplanation = this.explainLinks(emailData, ipLink, suspiciousTLD);
            if (linkExplanation.examples.length > 0) {
                evidence.push({
                    type: 'links',
                    label: 'Suspicious links',
                    value: linkExplanation.examples.join(', ')
                });
            }
        }

        // 6. High ML confidence (if no other strong signals)
        if (issueTypes.length === 0 && analysisResult.phishingProbability >= 0.7) {
            hasHighMLConfidence = true;
            issueTypes.push('phishing patterns');
        }

        // Build comprehensive summary
        const summary = this.buildComprehensiveSummary(
            emailData,
            issueTypes,
            hasSenderMismatch,
            hasBlocklist,
            hasNoEncryption,
            hasUrgency,
            hasSuspiciousLinks,
            hasHighMLConfidence
        );

        return {
            summary: summary,
            details: [],
            evidence: evidence
        };
    }

    /**
     * Build a comprehensive summary sentence combining all detected issues
     */
    buildComprehensiveSummary(emailData, issueTypes, hasSenderMismatch, hasBlocklist,
                               hasNoEncryption, hasUrgency, hasSuspiciousLinks, hasHighMLConfidence) {
        // Single issue - be specific
        if (issueTypes.length === 1) {
            if (hasSenderMismatch) {
                return this.explainSenderMismatch(emailData);
            }
            if (hasBlocklist) {
                return `The sender "${emailData.senderEmail}" is on your blocked list.`;
            }
            if (hasNoEncryption) {
                return "This email was sent without encryption, which is unusual for legitimate organizations.";
            }
            if (hasUrgency) {
                return "This email uses urgent language to pressure you into acting quickly.";
            }
            if (hasSuspiciousLinks) {
                const ipLink = issueTypes.includes('IP address links');
                if (ipLink) {
                    return "This email contains links to IP addresses instead of proper domain names, which is highly suspicious.";
                } else {
                    return "This email contains links to domains with suspicious extensions often used by scammers.";
                }
            }
            if (hasHighMLConfidence) {
                return "This email's language and patterns are very similar to known phishing attempts.";
            }
        }

        // Multiple issues - combine them
        if (issueTypes.length === 2) {
            // Format: "This email has X and Y"
            return `This email has ${issueTypes[0]} and ${issueTypes[1]}.`;
        }

        if (issueTypes.length === 3) {
            // Format: "This email has X, Y, and Z"
            return `This email has ${issueTypes[0]}, ${issueTypes[1]}, and ${issueTypes[2]}.`;
        }

        if (issueTypes.length >= 4) {
            // Format: "This email has multiple red flags: X, Y, Z, and W"
            const lastIssue = issueTypes[issueTypes.length - 1];
            const otherIssues = issueTypes.slice(0, -1).join(', ');
            return `This email has multiple red flags: ${otherIssues}, and ${lastIssue}.`;
        }

        // Fallback
        return "This email contains multiple suspicious indicators.";
    }

    /**
     * Explain sender mismatch with specific examples
     */
    explainSenderMismatch(emailData) {
        const name = emailData.senderName || '';
        const email = emailData.senderEmail || '';

        // Try to extract email from name
        const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
        const matches = name.match(emailRegex);

        if (matches && matches.length > 0) {
            const nameEmail = matches[0];
            return `The sender's display name shows "${nameEmail}" but the actual email is "${email}". This is a common impersonation tactic.`;
        }

        return `The sender's name "${name}" doesn't match their email address "${email}", which is suspicious.`;
    }

    /**
     * Explain urgency with specific examples from email
     */
    explainUrgency(emailData, inSubject, inBody) {
        const urgencyKeywords = [
            'urgent', 'immediate', 'suspend', 'ban', 'close', 'verify',
            'action required', 'unauthorized', 'locked', 'restricted'
        ];

        const examples = [];

        if (inSubject && emailData.subject) {
            const found = this.findKeywords(emailData.subject.toLowerCase(), urgencyKeywords);
            if (found.length > 0) {
                examples.push(`"${emailData.subject}"`);
            }
        }

        if (inBody && emailData.bodyText && examples.length === 0) {
            // Find a sentence with urgency
            const sentences = emailData.bodyText.split(/[.!?]+/);
            for (const sentence of sentences) {
                const found = this.findKeywords(sentence.toLowerCase(), urgencyKeywords);
                if (found.length > 0) {
                    const trimmed = sentence.trim().substring(0, 80);
                    examples.push(`"${trimmed}${sentence.length > 80 ? '...' : ''}"`);
                    break;
                }
            }
        }

        let text = "The email uses urgent language to pressure you into acting quickly.";
        if (inSubject && inBody) {
            text = "The email repeatedly uses urgent language to create a sense of panic.";
        }

        return {
            text: text,
            examples: examples
        };
    }

    /**
     * Explain suspicious links with examples
     */
    explainLinks(emailData, hasIP, hasSuspiciousTLD) {
        const examples = [];
        const links = emailData.links || [];

        if (hasIP) {
            // Find IP address links
            for (const link of links) {
                try {
                    const url = new URL(link);
                    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) {
                        examples.push(url.hostname);
                        break;
                    }
                } catch (e) {
                    // Invalid URL, skip
                }
            }
        }

        if (hasSuspiciousTLD && examples.length === 0) {
            // Find suspicious TLD links
            const suspiciousTLDs = ['.xyz', '.top', '.gq', '.tk', '.ml', '.cf'];
            for (const link of links) {
                try {
                    const url = new URL(link);
                    const suspiciousTLD = suspiciousTLDs.find(tld => url.hostname.endsWith(tld));
                    if (suspiciousTLD) {
                        examples.push(url.hostname);
                        break;
                    }
                } catch (e) {
                    // Invalid URL, skip
                }
            }
        }

        let text = "";
        if (hasIP) {
            text = "The email contains links to IP addresses instead of proper domain names, which is highly suspicious.";
        } else if (hasSuspiciousTLD) {
            text = "The email contains links to domains with suspicious extensions often used by scammers.";
        }

        return {
            text: text,
            examples: examples
        };
    }

    /**
     * Find keywords in text
     */
    findKeywords(text, keywords) {
        const found = [];
        for (const keyword of keywords) {
            if (text.includes(keyword)) {
                found.push(keyword);
            }
        }
        return found;
    }
}

// Expose globally for content.js to use
window.ExplanationGenerator = new ExplanationGenerator();
