document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");
  const analysisText = document.getElementById("analysisText");
  const statusDiv = document.getElementById("status");

  // Helper to update UI
  function updateUI(response) {
    resultDiv.classList.remove("hidden");
    if (response && response.status === "scanned") {
      // Update status UI based on result
      if (response.result === "safe") {
        statusDiv.className = "status safe";
        statusDiv.querySelector(".icon").textContent = "🛡️";
        statusDiv.querySelector(".text").textContent = "Safe";
      } else if (response.result === "skipped") {
        statusDiv.className = "status skipped";
        statusDiv.querySelector(".icon").textContent = "⏭️";
        statusDiv.querySelector(".text").textContent = "Skipped";
      } else {
        statusDiv.className = "status danger";
        statusDiv.querySelector(".icon").textContent = "⚠️";
        statusDiv.querySelector(".text").textContent = "Suspicious";
      }
      // Show explanation

      const explanationSummary = document.getElementById("explanationSummary");
      const evidenceList = document.getElementById("evidenceList");
      const technicalDetails = document.getElementById("technicalDetails");

      if (response.analysis && response.analysis.explanation) {
        const explanation = response.analysis.explanation;
        explanationSummary.textContent = explanation.summary;
        if (explanation.evidence && explanation.evidence.length > 0) {
          evidenceList.classList.remove("hidden");
          let evidenceHtml = '<ul class="evidence-items">';
          explanation.evidence.forEach((item) => {
            evidenceHtml += `<li><strong>${item.label}:</strong> ${item.value}</li>`;
          });
          evidenceHtml += "</ul>";
          evidenceList.innerHTML = evidenceHtml;
        } else {
          evidenceList.classList.add("hidden");
        }
        technicalDetails.style.display = "none";
      } else {
        explanationSummary.textContent = "";
        evidenceList.classList.add("hidden");
        technicalDetails.style.display = "block";
        if (response.analysis && response.analysis.flags.length > 0) {
          const flagsHtml = response.analysis.flags
            .map((flag) => `<li>${flag}</li>`)
            .join("");
          analysisText.innerHTML = `<ul style="text-align: left; margin-top: 8px;">${flagsHtml}</ul>`;
        } else {
          analysisText.textContent = "";
        }
      }

      // Update Score Bar
      const scoreContainer = document.getElementById("scoreContainer");
      const scoreArrow = document.getElementById("scoreArrow");

      if (response.analysis && typeof response.analysis.score === "number") {
        scoreContainer.classList.remove("hidden");
        // Clamp score between 0 and 100
        const score = Math.max(0, Math.min(100, response.analysis.score));
        scoreArrow.style.left = `${score}%`;
      } else {
        scoreContainer.classList.add("hidden");
      }

      // Display Threat Intelligence Results
      const threatIntelSection = document.getElementById("threatIntelSection");
      const threatIntelContent = document.getElementById("threatIntelContent");

      if (response.analysis && response.analysis.threatIntel && response.analysis.threatIntel.urls.length > 0) {
        threatIntelSection.classList.remove("hidden");
        const urlResult = response.analysis.threatIntel.urls[0];

        if (urlResult.verdict === "malicious") {
          threatIntelContent.innerHTML = `
            <div class="threat-intel-alert malicious">
              <strong>Malicious URL Detected</strong>
              <div class="threat-intel-url">${urlResult.url}</div>
              <div class="threat-intel-stats">
                Flagged by ${urlResult.malicious}/${urlResult.totalScanners} security vendors
              </div>
              <a href="${urlResult.reportUrl}" target="_blank" class="threat-intel-link">View full report →</a>
            </div>
          `;
        } else if (urlResult.verdict === "suspicious") {
          threatIntelContent.innerHTML = `
            <div class="threat-intel-alert suspicious">
              <strong>Suspicious URL</strong>
              <div class="threat-intel-url">${urlResult.url}</div>
              <div class="threat-intel-stats">
                Flagged by ${urlResult.threatCount}/${urlResult.totalScanners} vendors
              </div>
              <a href="${urlResult.reportUrl}" target="_blank" class="threat-intel-link">View full report →</a>
            </div>
          `;
        } else if (urlResult.verdict === "safe") {
          threatIntelContent.innerHTML = `
            <div class="threat-intel-alert safe">
              <strong>URL verified clean</strong>
              <div class="threat-intel-stats">
                0/${urlResult.totalScanners} vendors flagged this URL
              </div>
            </div>
          `;
        } else if (urlResult.submitted) {
          threatIntelContent.innerHTML = `
            <div class="threat-intel-alert unknown">
              <strong>URL submitted for scanning</strong>
              <div class="threat-intel-stats">
                Results will be available after analysis completes
              </div>
            </div>
          `;
        }
      } else {
        threatIntelSection.classList.add("hidden");
      }
    } else {
      const explanationSummary = document.getElementById("explanationSummary");
      explanationSummary.textContent = response
        ? response.message
        : "Scan failed.";
    }
  }

  // Check for cached result on load
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    if (tab && tab.url.includes("mail.google.com")) {
      try {
        const response = await chrome.tabs.sendMessage(tab.id, {
          action: "get_cache",
        });
        if (response) {
          updateUI(response);
        }
      } catch (e) {
        // Content script might not be ready or no cache
      }
    }
  });

  scanBtn.addEventListener("click", async () => {
    // Get the active tab
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (!tab.url.includes("mail.google.com")) {
      analysisText.textContent = "Please open Gmail to scan.";
      resultDiv.classList.remove("hidden");
      return;
    }

    // Send message to content script
    try {
      const response = await chrome.tabs.sendMessage(tab.id, {
        action: "scan_email",
      });
      updateUI(response);
    } catch (error) {
      console.error(error);
      analysisText.textContent =
        "Could not communicate with page. Try refreshing.";
      resultDiv.classList.remove("hidden");
    }
  });
});
