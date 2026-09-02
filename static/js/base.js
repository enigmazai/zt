// Auto-dismiss toasts
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.toast').forEach(t => {
    setTimeout(() => t.style.opacity = '0', 3500);
    setTimeout(() => t.remove(), 3800);
  });
});
