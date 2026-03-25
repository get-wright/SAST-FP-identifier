function updateIframeStyles(enable) {
  return enable;
}

function applyDark(button) {
  updateIframeStyles(true);
  document.querySelectorAll(".item").forEach((item) => item.classList.add("dark"));
  button.click();
}
