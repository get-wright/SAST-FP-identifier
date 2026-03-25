// frontend/js/upload.js

const MAX_FINDINGS_WARNING = 200;

let parsedJson = null;
let repoUrl = "";

export function initUpload(onSubmit) {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const prompt = document.getElementById("drop-zone-prompt");
  const info = document.getElementById("drop-zone-info");
  const warning = document.getElementById("drop-zone-warning");
  const fileName = document.getElementById("file-name");
  const findingCount = document.getElementById("finding-count");
  const clearBtn = document.getElementById("clear-file");
  const repoInput = document.getElementById("repo-url-input");
  const analyzeBtn = document.getElementById("analyze-btn");
  const gitTokenToggle = document.getElementById("git-token-toggle");
  const gitTokenField = document.getElementById("git-token-field");
  const gitTokenInput = document.getElementById("git-token-input");

  // Drag and drop
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });

  // Click to browse
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  // Clear file
  clearBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    resetFile();
  });

  // Repo URL
  repoInput.addEventListener("input", () => {
    repoUrl = repoInput.value.trim();
    updateButton();
  });

  // Git token toggle
  gitTokenToggle.addEventListener("click", () => {
    const expanded = gitTokenField.classList.toggle("hidden");
    gitTokenToggle.setAttribute("aria-expanded", !expanded);
    if (!expanded) gitTokenInput.focus();
  });

  // Submit — include git token if provided
  analyzeBtn.addEventListener("click", () => {
    if (parsedJson && repoUrl) {
      const gitToken = gitTokenInput.value.trim() || null;
      onSubmit(repoUrl, parsedJson, gitToken);
    }
  });

  function handleFile(file) {
    if (!file.name.endsWith(".json")) {
      showWarning("Please upload a .json file");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        parsedJson = JSON.parse(reader.result);
      } catch {
        showWarning("Invalid JSON file");
        return;
      }
      const count = (parsedJson.results || []).length;
      fileName.textContent = file.name;
      findingCount.textContent = `${count} finding${count !== 1 ? "s" : ""}`;
      prompt.classList.add("hidden");
      info.classList.remove("hidden");

      if (count > MAX_FINDINGS_WARNING) {
        showWarning(`File contains ${count} findings. Only the first ${MAX_FINDINGS_WARNING} will be analyzed.`);
      } else {
        warning.classList.add("hidden");
      }
      updateButton();
    };
    reader.readAsText(file);
  }

  function resetFile() {
    parsedJson = null;
    fileInput.value = "";
    prompt.classList.remove("hidden");
    info.classList.add("hidden");
    warning.classList.add("hidden");
    updateButton();
  }

  function showWarning(msg) {
    warning.textContent = msg;
    warning.classList.remove("hidden");
  }

  function updateButton() {
    analyzeBtn.disabled = !(parsedJson && repoUrl.startsWith("https://"));
  }
}

export function resetUpload() {
  parsedJson = null;
  repoUrl = "";
  document.getElementById("file-input").value = "";
  document.getElementById("repo-url-input").value = "";
  document.getElementById("git-token-input").value = "";
  document.getElementById("git-token-field").classList.add("hidden");
  document.getElementById("git-token-toggle").setAttribute("aria-expanded", "false");
  document.getElementById("drop-zone-prompt").classList.remove("hidden");
  document.getElementById("drop-zone-info").classList.add("hidden");
  document.getElementById("drop-zone-warning").classList.add("hidden");
  document.getElementById("analyze-btn").disabled = true;
}
