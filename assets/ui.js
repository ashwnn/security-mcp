document.addEventListener("click", async (event) => {
  const copyButton = event.target.closest("[data-copy-endpoint]");
  if (!copyButton) {
    return;
  }

  event.preventDefault();
  const endpoint = copyButton.getAttribute("data-copy-endpoint") || "";
  if (!endpoint) {
    return;
  }

  const original = copyButton.dataset.label || copyButton.textContent || "Copy";

  try {
    const response = await fetch(endpoint, { method: "POST" });
    if (!response.ok) {
      throw new Error("copy request failed");
    }
    const token = await response.text();
    await navigator.clipboard.writeText(token);
    copyButton.textContent = "Copied";
  } catch (_) {
    copyButton.textContent = "Copy failed";
  }

  window.setTimeout(() => {
    copyButton.textContent = original;
  }, 1200);
});
