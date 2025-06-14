
        // Application State
        let passwords = [];
        let currentEditId = null;
        let isVaultUnlocked = false;
        let masterPassword = ''; // Will be set when user enters master password

        // Initialize app
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });

        async function deriveKey(masterPassword, salt) {
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                enc.encode(masterPassword),
                { name: "PBKDF2" },
                false,
                ["deriveKey"]
            );
            return await crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
        }

        async function encryptAES(plainText, key) {
            const enc = new TextEncoder();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                enc.encode(plainText)
            );
            return {
                ciphertext: Array.from(new Uint8Array(encrypted)),
                iv: Array.from(iv)
            };
        }

        async function decryptAES(ciphertext, iv, key) {
            const data = new Uint8Array(ciphertext);
            const ivBytes = new Uint8Array(iv);
            
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBytes
                },
                key,
                data
            );
        
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        }

        function getCookie(name) {
            const nameEQ = name + "=";
            const ca = document.cookie.split(';');
            for (let i = 0; i < ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) === ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
            }
            return null;
        }

        function deleteCookie(name) {
            document.cookie = name + '=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        }

        // Master password handling
        document.getElementById('masterPasswordForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const masterPasswordInput = document.getElementById('masterPasswordInput').value;
            const errorDiv = document.getElementById('masterPasswordError');
            const response = await fetch('/app', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({master_password: masterPasswordInput})
            });
            const result = await response.json();

            if (result.success) {
                masterPassword = masterPasswordInput; // Store master password for encryption
                unlockVault();
                errorDiv.classList.remove('show');
            } else {
                errorDiv.classList.add('show');
            }
        });

        function unlockVault() {
            isVaultUnlocked = true;
            document.getElementById('masterPasswordScreen').classList.add('hidden');
            loadPasswordsFromDatabase();
        }

        function lockVault() {
            isVaultUnlocked = false;
            document.getElementById('masterPasswordScreen').classList.remove('hidden');
            document.getElementById('masterPasswordInput').value = '';
            passwords = [];
            renderPasswords();
        }

        // API Functions
        async function loadPasswords() {
            await loadPasswordsFromDatabase();
        }

        // Load passwords from database
        async function loadPasswordsFromDatabase() {
            try {
                const response = await fetch('/api/passwords');
                const data = await response.json();
                
                if (data.success) {
                    passwords = await Promise.all(data.passwords.map(async (p) => {
                        const salt = new Uint8Array(p.password.salt);
                        const iv = new Uint8Array(p.password.iv);
                        const ciphertext = p.password.ciphertext;

                        const key = await deriveKey(masterPassword, salt);
                        const decryptedpass = await decryptAES(ciphertext, iv, key);
                        return {
                            id: p._id,
                            service: p.website,
                            website_url: p.website_url,
                            username: p.username,
                            password: decryptedpass,
                            notes: p.notes || '',
                            createdAt: new Date(p.createdAt),
                            updatedAt: new Date(p.updatedAt)
                        };
                    }));
                    renderPasswords();
                } else {
                    console.error('Error loading passwords:', data.message);
                    showNotification('Error loading passwords', 'error');
                }
            } catch (error) {
                console.error('Error loading passwords:', error);
                showNotification('Error connecting to vault', 'error');
            }
        }

        // Save password to database
        async function savePasswordToDatabase(passwordData, isUpdate = false, passwordId = null) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const key = await deriveKey(masterPassword, salt);
            const encryptedPassword = await encryptAES(passwordData.password, key);
        
            // Attach salt to encryptedPassword object
            encryptedPassword.salt = Array.from(salt);

            try {
                const url = isUpdate ? `/api/passwords/${passwordId}` : '/api/passwords';
                const method = isUpdate ? 'PUT' : 'POST';
                
                // Convert frontend format to database format
                const dbPasswordData = {
                    website: passwordData.service,
                    website_url: passwordData.url,
                    username: passwordData.username,
                    password: encryptedPassword,
                    notes: passwordData.notes || ''
                };
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(dbPasswordData)
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showNotification(`Password ${isUpdate ? 'updated' : 'saved'} successfully`, 'success');
                    // Reload passwords from database to ensure sync
                    await loadPasswordsFromDatabase();
                    return true;
                } else {
                    console.error('Failed to save password:', data.message);
                    showNotification(`Failed to ${isUpdate ? 'update' : 'save'} password`, 'error');
                    return false;
                }
            } catch (error) {
                console.error('Error saving password:', error);
                showNotification('Error connecting to vault', 'error');
                return false;
            }
        }

        // Delete password from database
        async function deletePasswordFromDatabase(passwordId) {
            try {
                const response = await fetch(`/api/passwords/${passwordId}`, {
                    method: 'DELETE'
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showNotification('Password deleted successfully', 'success');
                    // Reload passwords from database to ensure sync
                    await loadPasswordsFromDatabase();
                    return true;
                } else {
                    console.error('Failed to delete password:', data.message);
                    showNotification('Failed to delete password', 'error');
                    return false;
                }
            } catch (error) {
                console.error('Error deleting password:', error);
                showNotification('Error connecting to vault', 'error');
                return false;
            }
        }

        // UI Functions
        function renderPasswords() {
            const grid = document.getElementById('passwordGrid');
            grid.innerHTML = '';

            passwords.forEach(password => {
                const card = document.createElement('div');
                card.className = 'password-card';
                card.innerHTML = `
                    <div class="card-header">
                        <h3 class="card-title">${password.service}</h3>
                        <div class="card-actions">
                            <button class="action-btn edit-btn" data-id="${password.id}">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="action-btn delete-btn" data-id="${password.id}">
                                <i class="fas fa-trash"></i>
                            </button>
                            <button class="action-btn copy-btn" style="cursor: pointer;" data-id="${password.id}">
                                <i class="fas fa-copy"></i>
                            </button>
                            
                        </div>
                    </div>
                    <div class="card-details">
                        <div class="detail-item">
                            <span class="detail-label">Username:</span>
                            <span class="detail-value" data-value="${password.username}">${password.username}</span>
                            
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Password:</span>
                            <span class="detail-value password-masked" data-value="${password.password}">••••••••</span>
                            <i class="fas fa-eye toggle-password" onclick="togglePasswordVisibility(this.previousElementSibling)"></i>
                            
                        </div>
                        ${password.notes ? `
                        <div class="detail-item">
                            <span class="detail-label">Notes:</span>
                            <span class="detail-value">${password.notes}</span>
                        </div>
                        ` : ''}
                    </div>
                `;

                // Add event listeners for edit and delete buttons
                const editBtn = card.querySelector('.edit-btn');
                const deleteBtn = card.querySelector('.delete-btn');
                const copybtn = card.querySelector('.copy-btn');

                copybtn.addEventListener('click', () => {
                    const passwordElement = card.querySelector('.detail-value.password-masked[data-value]');
                    copyToClipboard(passwordElement);
                    showNotification('Password copied to clipboard', 'success');
                });

                editBtn.addEventListener('click', () => openEditModal(password));
                deleteBtn.addEventListener('click', () => confirmDelete(password.id));

                grid.appendChild(card);
            });
        }

        function setupEventListeners() {
            // Add Password Button
            document.getElementById('addPasswordBtn').addEventListener('click', () => {
                currentEditId = null;
                document.getElementById('modalTitle').textContent = 'Add New Password';
                document.getElementById('passwordForm').reset();
                document.getElementById('passwordModal').classList.add('active');
            });

            // Close Modal Button
            document.getElementById('closeModalBtn').addEventListener('click', () => {
                document.getElementById('passwordModal').classList.remove('active');
            });

            // Cancel Button
            document.getElementById('cancelBtn').addEventListener('click', () => {
                document.getElementById('passwordModal').classList.remove('active');
            });

            // Password Form Submit
            document.getElementById('passwordForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const passwordData = {
                    service: document.getElementById('serviceName').value,
                    url: document.getElementById('url').value,
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    notes: document.getElementById('notes').value
                };

                let success;
                if (currentEditId) {
                    success = await savePasswordToDatabase(passwordData, true, currentEditId);
                } else {
                    success = await savePasswordToDatabase(passwordData);
                }

                if (success) {
                    document.getElementById('passwordModal').classList.remove('active');
                }
            });

            // Search Input
            document.getElementById('searchInput').addEventListener('input', (e) => {
                const searchTerm = e.target.value.toLowerCase();
                const filteredPasswords = passwords.filter(p => 
                    p.service.toLowerCase().includes(searchTerm) ||
                    p.username.toLowerCase().includes(searchTerm)
                );
                renderFilteredPasswords(filteredPasswords);
            });

            // Refresh Button
            document.getElementById('refreshBtn').addEventListener('click', loadPasswords);

            // Lock Vault Button
            document.getElementById('lockVaultBtn').addEventListener('click', lockVault);
        }

        function renderFilteredPasswords(filteredPasswords) {
            const tempPasswords = passwords;
            passwords = filteredPasswords;
            renderPasswords();
            passwords = tempPasswords;
        }

        function openEditModal(password) {
            currentEditId = password.id;
            document.getElementById('modalTitle').textContent = 'Edit Password';
            document.getElementById('serviceName').value = password.service;
            document.getElementById('username').value = password.username;
            document.getElementById('password').value = password.password;
            document.getElementById('url').value = password.website_url;
            document.getElementById('notes').value = password.notes || '';
            document.getElementById('passwordModal').classList.add('active');
        }

        function confirmDelete(id) {
            if (confirm('Are you sure you want to delete this password?')) {
                deletePasswordFromDatabase(id);
            }
        }

        function togglePasswordVisibility(element) {
            const icon = element.nextElementSibling;
            if (element.classList.contains('password-masked')) {
                element.textContent = element.dataset.value;
                element.classList.remove('password-masked');
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                element.textContent = '••••••••';
                element.classList.add('password-masked');
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }

        async function copyToClipboard(element) {
            const textToCopy = element.dataset.value;
            try {
                await navigator.clipboard.writeText(textToCopy);

            } catch (err) {
                console.error('Failed to copy text: ', err);
            }
        }

        // Show notification with optional type
        function showNotification(message, type = 'success') {
            // Create temporary notification
            const notification = document.createElement('div');
            const bgColor = type === 'error' ? 'var(--error)' : 'var(--success)';
            
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: ${bgColor};
                color: white;
                padding: 1rem 1.5rem;
                border-radius: var(--radius-sm);
                box-shadow: var(--shadow-lg);
                z-index: 1001;
                animation: slideIn 0.3s ease;
            `;
            notification.textContent = message;
            
            // Add keyframes for animation
            if (!document.querySelector('#notification-styles')) {
                const style = document.createElement('style');
                style.id = 'notification-styles';
                style.textContent = `
                    @keyframes slideIn {
                        from { transform: translateX(100%); opacity: 0; }
                        to { transform: translateX(0); opacity: 1; }
                    }
                    @keyframes slideOut {
                        from { transform: translateX(0); opacity: 1; }
                        to { transform: translateX(100%); opacity: 0; }
                    }
                `;
                document.head.appendChild(style);
            }
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        // Calculate password strength
        function calculatePasswordStrength(password) {
            let score = 0;
            let feedback = [];

            if (password.length >= 8) score++;
            if (password.length >= 12) score++;
            if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
            if (/\d/.test(password)) score++;
            if (/[^a-zA-Z0-9]/.test(password)) score++;

            if (score <= 2) {
                return { score: Math.min(score, 2), level: 'Weak', color: 'var(--error)' };
            } else if (score <= 3) {
                return { score: 3, level: 'Medium', color: 'var(--warning)' };
            } else {
                return { score: 4, level: 'Strong', color: 'var(--success)' };
            }
        }

        // Generate strength indicator dots
        function generateStrengthDots(password) {
            const strength = calculatePasswordStrength(password);
            const dots = [];
            
            for (let i = 0; i < 4; i++) {
                let className = 'strength-dot';
                if (i < strength.score) {
                    className += strength.score <= 2 ? ' weak' : strength.score <= 3 ? ' medium' : ' strong';
                }
                dots.push(`<div class="${className}"></div>`);
            }
            
            return dots.join('');
        }

        // Auto-lock after inactivity (optional feature)
        let inactivityTimer;
        const INACTIVITY_TIME = 30 * 60 * 1000; // 30 minutes

        function resetInactivityTimer() {
            clearTimeout(inactivityTimer);
            if (isVaultUnlocked) {
                inactivityTimer = setTimeout(() => {
                    lockVault();
                    showNotification('Vault locked due to inactivity');
                }, INACTIVITY_TIME);
            }
        }

        // Reset timer on user interaction
        document.addEventListener('mousedown', resetInactivityTimer);
        document.addEventListener('keypress', resetInactivityTimer);
        document.addEventListener('scroll', resetInactivityTimer);
        document.addEventListener('touchstart', resetInactivityTimer);

        // Export/Import functionality (Updated to use database data)
        async function exportPasswords() {
            try {
                // Get fresh data from database
                const response = await fetch('/api/passwords');
                const data = await response.json();
                
                if (!data.success) {
                    showNotification('Failed to fetch passwords for export', 'error');
                    return;
                }
                
                const exportData = {
                    version: '1.0',
                    exported: new Date().toISOString(),
                    passwords: data.passwords.map(p => ({
                        website: p.website,
                        username: p.username,
                        password: btoa(p.password), // Simple encoding for demo
                        website_url: p.website_url,
                        notes: p.notes,
                        createdAt: p.createdAt
                    }))
                };
                
                const dataStr = JSON.stringify(exportData, null, 2);
                const dataBlob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(dataBlob);
                
                const link = document.createElement('a');
                link.href = url;
                link.download = `securepass-backup-${new Date().toISOString().split('T')[0]}.json`;
                link.click();
                
                URL.revokeObjectURL(url);
                showNotification('Passwords exported successfully!');
                
            } catch (error) {
                console.error('Export error:', error);
                showNotification('Error exporting passwords', 'error');
            }
        }

        // Add export button to sidebar
        const exportBtn = document.createElement('div');
        exportBtn.className = 'nav-item';
        exportBtn.innerHTML = '<i class="fas fa-download"></i><span>Export</span>';
        exportBtn.addEventListener('click', exportPasswords);
        document.querySelector('.nav-menu').appendChild(exportBtn);

        // Initialize inactivity timer
        resetInactivityTimer();
 