document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('result');
    const analysisText = document.getElementById('analysisText');
    const statusDiv = document.getElementById('status');

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

            resultDiv.classList.remove('hidden');

            if (response && response.status === "scanned") {
                analysisText.textContent = `Scan Complete: ${response.result.toUpperCase()}`;

                // Update status UI based on result
                if (response.result === 'safe') {
                    statusDiv.className = 'status safe';
                    statusDiv.querySelector('.text').textContent = 'Safe';
                    statusDiv.querySelector('.icon').textContent = '🛡️';
                } else {
                    statusDiv.className = 'status danger';
                    statusDiv.querySelector('.text').textContent = 'Suspicious';
                    statusDiv.querySelector('.icon').textContent = '⚠️';
                }
            } else {
                analysisText.textContent = response ? response.message : "Scan failed.";
            }
        } catch (error) {
            console.error(error);
            analysisText.textContent = "Could not communicate with page. Try refreshing.";
            resultDiv.classList.remove('hidden');
        }
    });
});
