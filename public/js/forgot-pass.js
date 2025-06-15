
const form = document.getElementById('forgotPasswordForm');
const emailInput = document.getElementById('email');
const emailError = document.getElementById('emailError');

// Email validation
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Show error
function showError(message) {
  emailError.textContent = message;
  emailError.classList.add('show');
  emailInput.classList.add('error');
  emailInput.setAttribute("aria-invalid", "true");
}

// Hide error
function hideError() {
  emailError.textContent = '';
  emailError.classList.remove('show');
  emailInput.classList.remove('error');
  emailInput.removeAttribute("aria-invalid");
}

emailInput.addEventListener('input', function () {
  if (!this.value.trim()) {
    hideError();
  } else if (!validateEmail(this.value)) {
    showError('Please enter a valid email address');
  } else {
    hideError();
  }
});

form.addEventListener('submit', function (e) {
  if (!emailInput.value.trim()) {
    e.preventDefault();
    showError('Email address is required');
    emailInput.focus();
    return;
  }
  if (!validateEmail(emailInput.value.trim())) {
    e.preventDefault();
    showError('Please enter a valid email address');
    emailInput.focus();
    return;
  }
});

// Floating label effect color
emailInput.addEventListener('focus', function () {
  this.parentElement.parentElement.querySelector('label').style.color = '#667eea';
});
emailInput.addEventListener('blur', function () {
  this.parentElement.parentElement.querySelector('label').style.color = '#4a5568';
});
