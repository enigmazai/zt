/**
 * Auth page — slider + UX enhancements
 */

const SLIDES = { login: 0, register: 1, 'role-info': 2 };
let currentSlide = 0;

function slideTo(name) {
  const idx = SLIDES[name];
  if (idx === undefined) return;
  currentSlide = idx;
  const slider = document.getElementById('authSlider');
  if (slider) slider.style.transform = `translateX(-${idx * 100}%)`;

  // Update dots
  document.querySelectorAll('.dot').forEach((d, i) => {
    d.classList.toggle('dot--active', i === idx);
  });

  // Scroll into view on mobile
  const panel = document.getElementById('authPanel');
  if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Focus first input in new slide
  setTimeout(() => {
    const slides = document.querySelectorAll('.auth-slide');
    const activeSlide = slides[idx];
    if (activeSlide) {
      const firstInput = activeSlide.querySelector('input:not([type=radio]):not([type=hidden])');
      if (firstInput) firstInput.focus();
    }
  }, 460);
}

function togglePw(btn) {
  const wrap  = btn.closest('.input-wrap');
  const input = wrap.querySelector('input');
  const isText = input.type === 'text';
  input.type = isText ? 'password' : 'text';
  btn.setAttribute('aria-label', isText ? 'Show password' : 'Hide password');
}

// Add loading state to submit buttons
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.auth-form').forEach(form => {
    form.addEventListener('submit', e => {
      const btn = form.querySelector('button[type=submit]');
      if (btn) {
        btn.classList.add('btn--loading');
        btn.textContent = 'Please wait…';
      }
    });
  });

  // Auto-dismiss toasts after 4s
  document.querySelectorAll('.toast').forEach(toast => {
    setTimeout(() => toast.remove(), 4000);
  });
});
