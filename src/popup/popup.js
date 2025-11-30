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
