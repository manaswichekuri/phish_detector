document.getElementById('checkBtn').addEventListener('click', () => {
    const url = document.getElementById('urlInput').value.trim();
    const resultEl = document.getElementById('result');

    if (!url) {
        resultEl.textContent = "Please enter a URL!";
        resultEl.style.color = "red";
        return;
    }

    // For now, just a dummy check
    if (url.includes("phish")) {
        resultEl.textContent = "⚠ This URL might be phishing!";
        resultEl.style.color = "red";
    } else {
        resultEl.textContent = "✅ URL seems safe.";
        resultEl.style.color = "green";
    }
});