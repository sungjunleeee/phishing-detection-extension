document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");
  const analysisText = document.getElementById("analysisText");
  const statusDiv = document.getElementById("status");
  const scoreContainer = document.getElementById("scoreContainer");
  const scoreArrow = document.getElementById("scoreArrow");
  const explanationSummary = document.getElementById("explanationSummary");
  const evidenceList = document.getElementById("evidenceList");

  function updateUI(response) {
    resultDiv.classList.remove("hidden");
    analysisText.innerHTML = "";

    if (!response || response.status !== "scanned") {
      explanationSummary.textContent = response?.message || "Scan failed.";
      statusDiv.className = "status danger";
      statusDiv.querySelector(".icon").textContent = "❌";
      statusDiv.querySelector(".text").textContent = "Error";
      scoreContainer.classList.add("hidden");
      return;
    }

    // update status
    const iconSpan = statusDiv.querySelector(".icon");
    const textSpan = statusDiv.querySelector(".text");
    
    if (response.result === "safe") {
      statusDiv.className = "status safe";
      iconSpan.textContent = "🛡️";
      textSpan.textContent = "Safe";
    } else if (response.result === "skipped") {
      statusDiv.className = "status skipped";
      iconSpan.textContent = "⏭️";
      textSpan.textContent = "Skipped";
    } else {
      statusDiv.className = "status danger";
      iconSpan.textContent = "⚠️";
      textSpan.textContent = "Suspicious";
    }

    // analysis displ=lay
    let displayHTML = "";

    // Rule-based score
    if (typeof response.analysis?.score === "number") {
      const score = response.analysis.score;
      const scoreColor = score > 60 ? "#f44336" : score > 30 ? "#ff9800" : "#4caf50";

      displayHTML += `
        <div style="background: #f5f5f5;
                    padding: 10px;
                    border-radius: 6px;
                    margin-bottom: 10px;
                    border-left: 4px solid ${scoreColor};">
          <div style="display: flex;
                      justify-content: space-between;
                      align-items: center;">
            <span style="font-size: 12px; color: #666;">
              <strong>📊 Detection Score</strong>
            </span>
            <span style="font-size: 16px; font-weight: bold; color: ${scoreColor};">
              ${score}/100
            </span>
          </div>
        </div>
      `;
    }

    // Flags or positive message
    if (response.analysis?.flags?.length > 0) {
      displayHTML += `
        <div style="margin-bottom: 10px;">
          <div style="font-size: 12px;
                      font-weight: 600;
                      color: #666;
                      margin-bottom: 6px;">
            ⚠️ Detected Issues:
          </div>
          <ul style="text-align: left;
                     margin: 0;
                     padding-left: 20px;
                     font-size: 12px;
                     line-height: 1.7;">
      `;
      
      response.analysis.flags.forEach(flag => {
        displayHTML += `<li style="margin-bottom: 4px; color: #d32f2f;">${flag}</li>`;
      });
      
      displayHTML += `</ul></div>`;
      
    } else if (response.result === "safe") {
      displayHTML += `
        <div style="padding: 10px;
                    background: #e8f5e9;
                    border-radius: 6px;
                    text-align: center;
                    margin-bottom: 10px;">
          <span style="font-size: 12px; color: #2e7d32; font-weight: 500;">
            ✓ No suspicious patterns detected
          </span>
        </div>
      `;
    } else if (response.result === "skipped") {
      displayHTML += `
        <div style="padding: 10px;
                    background: #f5f5f5;
                    border-radius: 6px;
                    text-align: center;
                    margin-bottom: 10px;">
          <span style="font-size: 12px; color: #666; font-weight: 500;">
            ℹ️ Verified sender or allowlisted
          </span>
        </div>
      `;
    }

    analysisText.innerHTML = displayHTML;

    //Score bar positioning 
    if (scoreContainer && scoreArrow && typeof response.analysis?.score === "number") {
      scoreContainer.classList.remove("hidden");
      
      const rawScore = response.analysis.score;
      let position;
      
      if (response.result === "safe") {
        // Safe: 0-25% (far left)
        position = Math.min(rawScore, 30) / 30 * 25;
      } else if (response.result === "skipped") {
        // Skipped: 50% (center)
        position = 50;
      } else {
        // Suspicious: 75-100% (far right)
        position = 75 + (Math.min(Math.max(rawScore, 40), 100) - 40) / 60 * 25;
      }

      scoreArrow.style.left = `${Math.max(0, Math.min(100, position))}%`;
    } else {
      scoreContainer.classList.add("hidden");
    }
  }

  // --- Load cached result ---
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    if (tab?.url?.includes("mail.google.com")) {
      try {
        const response = await chrome.tabs.sendMessage(tab.id, { action: "get_cache" });
        if (response) updateUI(response);
      } catch (e) {
        // No cache available
      }
    }
  });

  // scan button
  scanBtn.addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab?.url?.includes("mail.google.com")) {
      analysisText.innerHTML = `
        <div style="color: #f44336; padding: 10px; text-align: center;">
          ⚠️ Please open Gmail to scan emails.
        </div>
      `;
      resultDiv.classList.remove("hidden");
      return;
    }

    try {
      // Show loading state
      scanBtn.disabled = true;
      scanBtn.innerHTML = "⏳ Scanning...";
      scanBtn.style.opacity = "0.7";

      statusDiv.className = "status warning";
      statusDiv.querySelector(".icon").textContent = "⏳";
      statusDiv.querySelector(".text").textContent = "Analyzing...";

      // Scan email
      const response = await chrome.tabs.sendMessage(tab.id, { action: "scan_email" });
      updateUI(response);
      
    } catch (error) {
      console.error(error);
      
      analysisText.innerHTML = `
        <div style="padding: 15px;
                    background: #ffebee;
                    border-radius: 8px;
                    text-align: center;">
          <div style="color: #c62828; font-weight: 600; margin-bottom: 8px;">
            ❌ Connection Error
          </div>
          <div style="font-size: 12px; color: #666; line-height: 1.6;">
            Cannot communicate with Gmail.<br>
            Refresh the page and try again.
          </div>
        </div>
      `;
      
      statusDiv.className = "status danger";
      statusDiv.querySelector(".icon").textContent = "❌";
      statusDiv.querySelector(".text").textContent = "Error";
      
    } finally {
      // Restore button
      scanBtn.disabled = false;
      scanBtn.innerHTML = "🔍 Scan Email";
      scanBtn.style.opacity = "1";
    }
  });
});