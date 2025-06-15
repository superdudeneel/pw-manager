
        class PasswordReset {
            constructor() {
                this.form = document.getElementById('resetPasswordForm');
                this.newPasswordInput = document.getElementById('newPassword');
                this.confirmPasswordInput = document.getElementById('confirmPassword');
                this.resetBtn = document.getElementById('resetBtn');
                this.errorMessage = document.getElementById('errorMessage');
                this.successMessage = document.getElementById('successMessage');
                
                this.requirements = {
                    length: document.getElementById('length'),
                    uppercase: document.getElementById('uppercase'),
                    lowercase: document.getElementById('lowercase'),
                    number: document.getElementById('number'),
                    special: document.getElementById('special')
                };
                
                this.strengthBar = document.getElementById('strengthBar');
                this.strengthText = document.getElementById('strengthText');
                
                // Get token from URL
                this.token = new URLSearchParams(window.location.search).get('token');
                
                this.init();
            }

            init() {
                // Check if token exists
                if (!this.token) {
                    this.showError('Invalid or missing reset token. Please request a new password reset.');
                    this.resetBtn.disabled = true;
                    return;
                }

                // Password visibility toggles
                document.querySelectorAll('.toggle-password').forEach(btn => {
                    btn.addEventListener('click', (e) => this.togglePasswordVisibility(e));
                });

                // Real-time password validation
                this.newPasswordInput.addEventListener('input', () => {
                    this.validatePassword();
                    this.checkPasswordStrength();
                });

                this.confirmPasswordInput.addEventListener('input', () => {
                    this.validatePasswordMatch();
                });

                // Form submission
                this.form.addEventListener('submit', (e) => this.handleSubmit(e));
            }

            togglePasswordVisibility(e) {
                const targetId = e.target.getAttribute('data-target');
                const input = document.getElementById(targetId);
                const button = e.target;

                if (input.type === 'password') {
                    input.type = 'text';
                    button.textContent = '🙈';
                } else {
                    input.type = 'password';
                    button.textContent = '👁️';
                }
            }

            validatePassword() {
                const password = this.newPasswordInput.value;
                const checks = {
                    length: password.length >= 8,
                    uppercase: /[A-Z]/.test(password),
                    lowercase: /[a-z]/.test(password),
                    number: /\d/.test(password),
                    special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
                };

                Object.keys(checks).forEach(key => {
                    if (this.requirements[key]) {
                        if (checks[key]) {
                            this.requirements[key].classList.add('valid');
                        } else {
                            this.requirements[key].classList.remove('valid');
                        }
                    }
                });

                return Object.values(checks).every(check => check);
            }

            checkPasswordStrength() {
                const password = this.newPasswordInput.value;
                let strength = 0;
                let strengthClass = '';
                let strengthLabel = '';

                if (password.length >= 8) strength++;
                if (/[A-Z]/.test(password)) strength++;
                if (/[a-z]/.test(password)) strength++;
                if (/\d/.test(password)) strength++;
                if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;

                const percentage = (strength / 5) * 100;

                switch (strength) {
                    case 0:
                    case 1:
                        strengthClass = 'strength-weak';
                        strengthLabel = 'Very Weak';
                        break;
                    case 2:
                        strengthClass = 'strength-weak';
                        strengthLabel = 'Weak';
                        break;
                    case 3:
                        strengthClass = 'strength-fair';
                        strengthLabel = 'Fair';
                        break;
                    case 4:
                        strengthClass = 'strength-good';
                        strengthLabel = 'Good';
                        break;
                    case 5:
                        strengthClass = 'strength-strong';
                        strengthLabel = 'Strong';
                        break;
                }

                this.strengthBar.style.width = `${percentage}%`;
                this.strengthBar.className = `strength-fill ${strengthClass}`;
                this.strengthText.textContent = password ? `Password Strength: ${strengthLabel}` : 'Password strength will appear here';
            }

            validatePasswordMatch() {
                const password = this.newPasswordInput.value;
                const confirmPassword = this.confirmPasswordInput.value;

                if (confirmPassword && password !== confirmPassword) {
                    this.confirmPasswordInput.style.borderColor = '#e74c3c';
                    return false;
                } else {
                    this.confirmPasswordInput.style.borderColor = '#e1e5e9';
                    return true;
                }
            }

            showError(message) {
                this.errorMessage.textContent = message;
                this.errorMessage.style.display = 'block';
                this.successMessage.style.display = 'none';
            }

            showSuccess(message) {
                this.successMessage.textContent = message;
                this.successMessage.style.display = 'block';
                this.errorMessage.style.display = 'none';
            }

            hideMessages() {
                this.errorMessage.style.display = 'none';
                this.successMessage.style.display = 'none';
            }

            async handleSubmit(e) {
                e.preventDefault();
                this.hideMessages();

                const password = this.newPasswordInput.value;
                const confirmPassword = this.confirmPasswordInput.value;

                // Validate password requirements
                if (!this.validatePassword()) {
                    this.showError('Please ensure your password meets all requirements.');
                    return;
                }

                // Validate password match
                if (password !== confirmPassword) {
                    this.showError('Passwords do not match. Please try again.');
                    return;
                }

                // Show loading state
                this.resetBtn.disabled = true;
                document.querySelector('.btn-text').style.opacity = '0';
                document.querySelector('.btn-loader').style.display = 'block';

                try {
                    const response = await fetch(`/reset-pass?token=${this.token}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            newPassword: password,
                            confirmPassword: confirmPassword
                        })
                    });

                    const data = await response.json();

                    if (data.success) {
                        this.showSuccess(data.message);
                        
                        // Redirect to login after success
                        setTimeout(() => {
                            window.location.href = '/login';
                        }, 2000);
                        
                    } else {
                        this.showError(data.message || 'Failed to reset password. Please try again.');
                    }
                    
                } catch (error) {
                    console.error('Password reset error:', error);
                    this.showError('Network error. Please check your connection and try again.');
                } finally {
                    // Reset button state
                    this.resetBtn.disabled = false;
                    document.querySelector('.btn-text').style.opacity = '1';
                    document.querySelector('.btn-loader').style.display = 'none';
                }
            }
        }

        // Initialize the password reset functionality
        document.addEventListener('DOMContentLoaded', () => {
            new PasswordReset();
        });
