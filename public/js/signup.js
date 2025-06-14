
const form = document.getElementById('signupForm');
const passwordInput = document.getElementById('password');
const strengthFill = document.getElementById('strengthFill');
const strengthText = document.getElementById('strengthText');
const successMessage = document.getElementById('successMessage');

// Password strength checker
passwordInput.addEventListener('input', function() {
    const password = this.value;
    const strength = calculatePasswordStrength(password);
    
    strengthFill.className = 'strength-fill';
    
    if (password.length === 0) {
        strengthText.textContent = 'Password strength will appear here';
        return;
    }
    
    if (strength < 2) {
        strengthFill.classList.add('strength-weak');
        strengthText.textContent = 'Weak password';
    } else if (strength < 3) {
        strengthFill.classList.add('strength-fair');
        strengthText.textContent = 'Fair password';
    } else if (strength < 4) {
        strengthFill.classList.add('strength-good');
        strengthText.textContent = 'Good password';
    } else {
        strengthFill.classList.add('strength-strong');
        strengthText.textContent = 'Strong password';
    }
});

function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    return strength;
}

form.addEventListener('submit', (event) => {
    event.preventDefault(); // Stop the default form action

    const button = document.querySelector('.signup-btn');
    const originalText = button.textContent;

    button.textContent = 'Creating account...';
    button.disabled = true;

    setTimeout(() => {
        successMessage.classList.add('show');
        button.textContent = originalText;
        button.disabled = false;

        // Auto-submit the form after a short delay
        setTimeout(() => {
            form.submit();
        }, 2000); // Submit 2 seconds after showing message

    }, 1000); // Show success message after 1 second
});
