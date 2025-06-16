
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

form.addEventListener('submit', async (event) => {
    event.preventDefault(); // Stop the default form action
    const formData = new FormData(form);
    const data = {
        username: formData.get("username"),
        email: formData.get('email'),
        password: formData.get("password")

    };
    const response = await fetch('/signup', {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    })
    const result = await response.json();
    if(!result.success){
        Swal.fire({
            title: 'Oops...',
            text: result.message,
            icon: 'error',
            confirmButtonText: 'Try Again',
            customClass: {
              confirmButton: 'my-confirm-button',
            },
            buttonsStyling: false,
            showCloseButton: true
        });
    }
    else{
        Swal.fire({
              title: 'Success',
              text: result.message,
              icon: 'success',
              confirmButtonText: 'OK',
              timer: 1420,
              customClass: {
                confirmButton: 'my-confirm-button',
              },
            }).then(()=>{
                window.location.href = result.redirect;

            })
    }
});
