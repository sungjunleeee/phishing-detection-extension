document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('result');
    const analysisText = document.getElementById('analysisText');
    const statusDiv = document.getElementById('status');

    // Helper to update UI
    function updateUI(response) {
        resultDiv.classList.remove('hidden');
        if (response && response.status === "scanned") {
            // Clear previous text
            analysisText.textContent = "";

            // Update status UI based on result
            if (response.result === 'safe') {
                statusDiv.className = 'status safe';
                statusDiv.querySelector('.icon').textContent = '🛡️';
                statusDiv.querySelector('.text').textContent = 'Safe';
            } else {
                statusDiv.className = 'status danger';
                statusDiv.querySelector('.icon').textContent = '⚠️';
                statusDiv.querySelector('.text').textContent = 'Suspicious';
            }

            // Show flags if any
            if (response.analysis && response.analysis.flags.length > 0) {
                const flagsHtml = response.analysis.flags.map(flag => `<li>${flag}</li>`).join('');
                analysisText.innerHTML += `<ul style="text-align: left; margin-top: 8px;">${flagsHtml}</ul>`;
            }
        } else {
            analysisText.textContent = response ? response.message : "Scan failed.";
        }
    }

    // Check for cached result on load
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];
        if (tab && tab.url.includes('mail.google.com')) {
            try {
                const response = await chrome.tabs.sendMessage(tab.id, { action: "get_cache" });
                if (response) {
                    updateUI(response);
                }
            } catch (e) {
                // Content script might not be ready or no cache
            }
        }
    });

    scanBtn.addEventListener('click', async () => {
        // Get the active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab.url.includes('mail.google.com')) {
            analysisText.textContent = "Please open Gmail to scan.";
            resultDiv.classList.remove('hidden');
            return;
        }

        // Send message to content script
        try {
            const response = await chrome.tabs.sendMessage(tab.id, { action: "scan_email" });
            updateUI(response);
        } catch (error) {
            console.error(error);
            analysisText.textContent = "Could not communicate with page. Try refreshing.";
            resultDiv.classList.remove('hidden');
        }
    });
});
