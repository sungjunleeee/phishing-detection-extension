document.addEventListener('DOMContentLoaded', () => {
    const autoscanToggle = document.getElementById('autoscanToggle');
    const allowlistInput = document.getElementById('allowlistInput');
    const addAllowlistBtn = document.getElementById('addAllowlistBtn');
    const allowlistUl = document.getElementById('allowlist');
    const blocklistInput = document.getElementById('blocklistInput');
    const addBlocklistBtn = document.getElementById('addBlocklistBtn');
    const blocklistUl = document.getElementById('blocklist');
    const statusDiv = document.getElementById('status');

    // Load settings
    chrome.storage.sync.get(['autoscan', 'allowlist', 'blocklist', 'threatIntel_enabled', 'api_virustotal'], (result) => {
        autoscanToggle.checked = result.autoscan || false;
        renderList(allowlistUl, result.allowlist || ['columbia.edu']);
        renderList(blocklistUl, result.blocklist || []);
        
        // Threat Intelligence settings
        document.getElementById('threatIntelToggle').checked = result.threatIntel_enabled || false;
        document.getElementById('virusTotalApiKey').value = result.api_virustotal || '';
    });

    // Autoscan Toggle
    autoscanToggle.addEventListener('change', () => {
        chrome.storage.sync.set({ autoscan: autoscanToggle.checked }, showStatus);
    });

    // Threat Intelligence Toggle
    document.getElementById('threatIntelToggle').addEventListener('change', () => {
        chrome.storage.sync.set({ 
            threatIntel_enabled: document.getElementById('threatIntelToggle').checked 
        }, showStatus);
    });

    // VirusTotal API Key
    document.getElementById('virusTotalApiKey').addEventListener('change', () => {
        chrome.storage.sync.set({ 
            api_virustotal: document.getElementById('virusTotalApiKey').value.trim() 
        }, showStatus);
    });

    // Allowlist Logic
    addAllowlistBtn.addEventListener('click', () => {
        addItem('allowlist', allowlistInput, allowlistUl);
    });

    // Blocklist Logic
    addBlocklistBtn.addEventListener('click', () => {
        addItem('blocklist', blocklistInput, blocklistUl);
    });

    function addItem(key, input, ul) {
        const value = input.value.trim().toLowerCase();
        if (!value) return;

        chrome.storage.sync.get([key], (result) => {
            const list = result[key] || [];
            if (!list.includes(value)) {
                list.push(value);
                chrome.storage.sync.set({ [key]: list }, () => {
                    renderList(ul, list);
                    input.value = '';
                    showStatus();
                });
            }
        });
    }

    function removeItem(key, value, ul) {
        chrome.storage.sync.get([key], (result) => {
            const list = result[key] || [];
            const newList = list.filter(item => item !== value);
            chrome.storage.sync.set({ [key]: newList }, () => {
                renderList(ul, newList);
                showStatus();
            });
        });
    }

    function renderList(ul, list) {
        ul.innerHTML = '';
        list.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;

            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Remove';
            deleteBtn.className = 'delete-btn';
            deleteBtn.onclick = () => removeItem(ul.id, item, ul);

            li.appendChild(deleteBtn);
            ul.appendChild(li);
        });
    }

    function showStatus() {
        statusDiv.classList.remove('hidden');
        setTimeout(() => {
            statusDiv.classList.add('hidden');
        }, 2000);
    }
});
