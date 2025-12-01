/**
 * Very very basic VirusTotal URL checker with basic caching and rate limiting (free tier has very strict limits so this is necessary)
 */
class ThreatIntelligence {
    constructor() {
        this.cache = new Map();
        this.CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
        this.requestQueue = [];
        this.lastRequestTime = 0;
        this.MIN_REQUEST_INTERVAL = 15000; // 15 seconds (4 requests/minute = 1 every 15s)
    }

    /**
     * check a single URL with VirusTotal
     * @param {string} url - URL to check
     * @param {string} apiKey - VirusTotal API key
     * @returns {Promise<Object>} Result object
     */
    async checkURL(url, apiKey) {
        // check cache first
        const cacheKey = this.normalizeURL(url);
        const cached = this.cache.get(cacheKey);
        
        if (cached && Date.now() < cached.expiresAt) {
            console.log('Threat Intel: Cache hit for', url);
            return cached.result;
        }

        // rate limiting
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.MIN_REQUEST_INTERVAL) {
            const waitTime = this.MIN_REQUEST_INTERVAL - timeSinceLastRequest;
            console.log(`Threat Intel: Rate limiting, waiting ${waitTime}ms`);
            await this.sleep(waitTime);
        }

        // call VirusTotal API
        try {
            const result = await this.queryVirusTotal(url, apiKey);
            this.lastRequestTime = Date.now();
            
            // Cache the result
            this.cache.set(cacheKey, {
                result: result,
                expiresAt: Date.now() + this.CACHE_TTL
            });
            
            return result;
        } catch (error) {
            console.error('Threat Intel: Error checking URL', error);
            return {
                verdict: 'unknown',
                error: error.message
            };
        }
    }

    /**
     * multiple URLS, will only check 1st URL bc of rate limit issues
     * @param {string[]} urls - Array of URLs
     * @param {string} apiKey - VirusTotal API key
     * @returns {Promise<Object>} Aggregated results
     */
    async checkURLs(urls, apiKey) {
        if (!urls || urls.length === 0) {
            return { verdict: 'unknown', urls: [] };
        }

        const firstUrl = urls[0];
        const result = await this.checkURL(firstUrl, apiKey);
        
        return {
            verdict: result.verdict,
            urls: [{
                url: firstUrl,
                ...result
            }],
            source: 'VirusTotal',
            note: urls.length > 1 ? `Checked 1 of ${urls.length} URLs (rate limit protection)` : null
        };
    }

    /**
     * VirusTotal API queries
     */
    async queryVirusTotal(url, apiKey) {
        // create URL id (base64 without padding)
        const urlId = btoa(url).replace(/=/g, '');
        
        // check if there's an existing analysis
        const lookupEndpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        
        const response = await fetch(lookupEndpoint, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey
            }
        });

        if (response.status === 404) {
            // if the url isn't already available, submit it for scanning
            return await this.submitURLForScanning(url, apiKey);
        }

        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const data = await response.json();
        return this.parseVirusTotalResults(data);
    }

    /**
     * submit URL for scanning (if not in db)
     */
    async submitURLForScanning(url, apiKey) {
        const submitEndpoint = 'https://www.virustotal.com/api/v3/urls';
        
        const formData = new URLSearchParams();
        formData.append('url', url);

        const response = await fetch(submitEndpoint, {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData
        });

        if (!response.ok) {
            throw new Error(`VirusTotal submit error: ${response.status}`);
        }

        // url has been submitted for scanning, results not ready yet
        return {
            verdict: 'unknown',
            message: 'URL submitted for scanning, results pending',
            submitted: true
        };
    }

    /**
     * parse VirusTotal response
     */
    parseVirusTotalResults(data) {
        const stats = data.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        
        const totalScanners = malicious + suspicious + harmless + undetected;
        const threatCount = malicious + suspicious;
        
        // Determine verdict
        let verdict = 'safe';
        if (malicious >= 5) {
            verdict = 'malicious';
        } else if (malicious >= 2 || suspicious >= 3) {
            verdict = 'suspicious';
        }
        
        return {
            verdict: verdict,
            malicious: malicious,
            suspicious: suspicious,
            harmless: harmless,
            totalScanners: totalScanners,
            threatCount: threatCount,
            reportUrl: `https://www.virustotal.com/gui/url/${data.data.id}`
        };
    }

    /**
     * normalize URL for caching
     */
    normalizeURL(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname.toLowerCase() + urlObj.pathname;
        } catch {
            return url.toLowerCase();
        }
    }

    /**
     * sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// make available globally
window.ThreatIntel = new ThreatIntelligence();
