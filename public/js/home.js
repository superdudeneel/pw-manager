class BreachDetection {
    constructor() {
        this.isScanning = false;
        this.scanProgress = 0;
        this.breachData = [];
        this.hibpApiKey = null; // Set this if you have a premium API key
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadBreachData();
        this.updateStats();
    }

    setupEventListeners() {
        // Navigation between tabs
        document.addEventListener('click', (e) => {
            if (e.target.closest('.nav-item')) {
                const navItem = e.target.closest('.nav-item');
                const text = navItem.querySelector('span')?.textContent;
                
                if (text === 'Detect Breaches') {
                    this.showBreachDetection();
                } else if (text === 'Passwords') {
                    this.showPasswordManager();
                }
            }
        });

        // Scan button
        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => this.startScan());
        }

        // Rescan button
        const rescanBtn = document.getElementById('rescanBtn');
        if (rescanBtn) {
            rescanBtn.addEventListener('click', () => this.startScan());
        }
    }

    showBreachDetection() {
        const passwordView = document.querySelector('.main-content');
        if (passwordView) {
            passwordView.style.display = 'none';
        }

        // Show breach detection view or create it
        let breachView = document.querySelector('.breach-detection-view');
        if (!breachView) {
            breachView = this.createBreachDetectionView();
            document.querySelector('.container').appendChild(breachView);
        }
        
        breachView.style.display = 'block';
        breachView.classList.add('active');

        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector('.nav-item:nth-child(2)').classList.add('active');
    }

    showPasswordManager() {
        // Hide breach detection view
        const breachView = document.querySelector('.breach-detection-view');
        if (breachView) {
            breachView.style.display = 'none';
            breachView.classList.remove('active');
        }

        // Show password manager
        const passwordView = document.querySelector('.main-content');
        if (passwordView) {
            passwordView.style.display = 'block';
        }

        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector('.nav-item:first-child').classList.add('active');
    }

    createBreachDetectionView() {
        const view = document.createElement('main');
        view.className = 'breach-detection-view';
        view.innerHTML = `
            <div class="breach-hero">
                <div class="breach-hero-icon">
                    <i class="fas fa-shield-virus"></i>
                </div>
                <h2>Breach Detection</h2>
                <p>Scan your passwords against known data breaches using Have I Been Pwned database. We check your credentials against millions of compromised passwords without exposing your data.</p>
                <div class="hibp-attribution">
                    <small>Powered by <a href="https://haveibeenpwned.com" target="_blank" rel="noopener" style = "color: white;">Have I Been Pwned</a></small>
                </div>
            </div>

            <div class="breach-stats">
                <div class="stat-card">
                    <div class="stat-icon safe">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-number" id="safeCount">-</div>
                    <div class="stat-label">Safe Passwords</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon warning">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-number" id="warningCount">-</div>
                    <div class="stat-label">Weak Passwords</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon danger">
                        <i class="fas fa-skull-crossbones"></i>
                    </div>
                    <div class="stat-number" id="breachedCount">-</div>
                    <div class="stat-label">Breached Passwords</div>
                </div>
            </div>

            <div class="breach-actions">
                <button class="btn btn-scan" id="scanBtn">
                    <i class="fas fa-search"></i>
                    <span>Start Security Scan</span>
                </button>
                <button class="btn btn-outline" id="rescanBtn" style="display: none;">
                    <i class="fas fa-sync-alt"></i>
                    <span>Scan Again</span>
                </button>
            </div>

            <div class="progress-bar" id="progressBar" style="display: none;">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="progress-text" id="progressText" style="display: none;">
                Initializing scan...
            </div>

            <div class="breach-results" id="breachResults">
                <!-- Results will be populated here -->
            </div>
        `;

        // Add event listeners for the new elements
        setTimeout(() => {
            const scanBtn = view.querySelector('#scanBtn');
            const rescanBtn = view.querySelector('#rescanBtn');
            
            if (scanBtn) {
                scanBtn.addEventListener('click', () => this.startScan());
            }
            if (rescanBtn) {
                rescanBtn.addEventListener('click', () => this.startScan());
            }
        }, 100);

        return view;
    }

    async sha1Hash(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex.toUpperCase();
    }
    async checkPasswordBreaches(password) {
        try {
            const hash = await this.sha1Hash(password);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);

            //api of have i been pwned
            
            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                method: 'GET',
                headers: {
                    'User-Agent': 'SecurePass-PasswordManager'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.text();
            const hashes = data.split('\n');
            
            for (let hashLine of hashes) {
                const [hashSuffix, count] = hashLine.trim().split(':');
                if (hashSuffix === suffix) {
                    return {
                        breached: true,
                        count: parseInt(count, 10)
                    };
                }
            }

            return {
                breached: false,
                count: 0
            };
        } catch (error) {
            console.error('Error checking password breaches:', error);
            // Return null to indicate API error, not breach status
            return null;
        }
    }

    async checkEmailBreaches(email) {
        try {
            const baseUrl = 'https://haveibeenpwned.com/api/v3/breachedaccount/';
            const headers = {
                'User-Agent': 'SecurePass-PasswordManager'
            };

            
            //doenst work because of the requirement of a paid api key 
            if (this.hibpApiKey) {
                headers['hibp-api-key'] = this.hibpApiKey;
            }

            const response = await fetch(`${baseUrl}${encodeURIComponent(email)}?truncateResponse=false`, {
                method: 'GET',
                headers: headers
            });

            if (response.status === 404) {
                // No breaches found
                return {
                    breached: false,
                    breaches: []
                };
            }

            if (!response.ok) {
                if (response.status === 429) {
                    throw new Error('Rate limit exceeded. Please try again later.');
                }
                if (response.status === 401) {
                    throw new Error('API key required for detailed breach information.');
                }
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const breaches = await response.json();
            return {
                breached: true,
                breaches: breaches || []
            };
        } catch (error) {
            console.error('Error checking email breaches:', error);
            return null;
        }
    }

    loadBreachData() {
        // Load cached breach data if available
        const storedData = localStorage.getItem('breachScanResults');
        const lastScanDate = localStorage.getItem('lastScanDate');
        
        if (storedData && lastScanDate) {
            const daysSinceLastScan = (Date.now() - new Date(lastScanDate).getTime()) / (1000 * 60 * 60 * 24);
            if (daysSinceLastScan < 7) { // Use cached data if less than 7 days old
                this.breachData = JSON.parse(storedData);
                return;
            }
        }
        
        // If no cached data or data is old, initialize empty
        this.breachData = [];
    }

    getStoredPasswords() {
        // Get passwords from the global passwords array (from your existing code)
        if (typeof passwords !== 'undefined' && passwords.length > 0) {
            return passwords.map(pwd => ({
                serviceName: pwd.service,
                username: pwd.username,
                password: pwd.password,
                url: pwd.website_url || ''
            }));
        }
        
        // Fallback to sample data for testing
        return [
            { serviceName: 'Gmail', username: 'user@gmail.com', password: 'password123' },
            { serviceName: 'GitHub', username: 'developer', password: 'SecureP@ss456' },
            { serviceName: 'Facebook', username: 'user123@email.com', password: 'MyFacebookPass' }
        ];
    }

    async generateRealBreachData() {
        const storedPasswords = this.getStoredPasswords();
        const breachData = [];

        for (let i = 0; i < storedPasswords.length; i++) {
            const pwd = storedPasswords[i];
            
            // Update progress
            this.updateScanProgress((i / storedPasswords.length) * 100, 
                `Checking ${pwd.serviceName}...`);

            // Check password against HIBP
            const passwordCheck = await this.checkPasswordBreaches(pwd.password);
            
            // Add delays to make sure the api call doesnt fail
            await this.delay(200);

            // Check email against HIBP (not included as the api key is paid)
            let emailCheck = null;
            if (pwd.username.includes('@')) {
                emailCheck = await this.checkEmailBreaches(pwd.username);
                await this.delay(200);
            }

            let status, details;
            
            if (passwordCheck === null) {
                // API error occurred
                status = 'warning';
                details = 'Unable to verify password security. Check your internet connection.';
            } else if (passwordCheck.breached) {
                status = 'danger';
                details = `This password has been found in ${passwordCheck.count.toLocaleString()} data breaches. Change it immediately!`;
            } else {
                // Password not breached, but check if email was breached
                if (emailCheck && emailCheck.breached) {
                    status = 'warning';
                    const breachNames = emailCheck.breaches.slice(0, 3).map(b => b.Name).join(', ');
                    details = `Your email was found in breaches: ${breachNames}${emailCheck.breaches.length > 3 ? ' and others' : ''}. Consider changing this password as a precaution.`;
                } else if (emailCheck === null && pwd.username.includes('@')) {
                    status = 'safe';
                    details = 'Password appears secure, but email breach status could not be verified.';
                } else {
                    status = 'safe';
                    details = 'No breaches detected. This password appears to be secure.';
                }
            }

            breachData.push({
                serviceName: pwd.serviceName,
                username: pwd.username,
                status: status,
                details: details,
                passwordBreached: passwordCheck ? passwordCheck.breached : null,
                passwordBreachCount: passwordCheck ? passwordCheck.count : 0,
                emailBreached: emailCheck ? emailCheck.breached : null,
                emailBreaches: emailCheck ? emailCheck.breaches : [],
                lastChecked: new Date().toISOString()
            });
        }

        return breachData;
    }

    updateScanProgress(percentage, message) {
        this.scanProgress = percentage;
        
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
        }
        
        if (progressText) {
            progressText.textContent = message;
        }
    }

    updateStats() {
        const safeCount = this.breachData.filter(item => item.status === 'safe').length;
        const warningCount = this.breachData.filter(item => item.status === 'warning').length;
        const breachedCount = this.breachData.filter(item => item.status === 'danger').length;

        const safeCountEl = document.getElementById('safeCount');
        const warningCountEl = document.getElementById('warningCount');
        const breachedCountEl = document.getElementById('breachedCount');

        if (safeCountEl) safeCountEl.textContent = safeCount;
        if (warningCountEl) warningCountEl.textContent = warningCount;
        if (breachedCountEl) breachedCountEl.textContent = breachedCount;
    }

    async startScan() {
        if (this.isScanning) return;

        this.isScanning = true;
        this.scanProgress = 0;

        const scanBtn = document.getElementById('scanBtn');
        const rescanBtn = document.getElementById('rescanBtn');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const breachResults = document.getElementById('breachResults');

        // Update UI
        if (scanBtn) {
            scanBtn.classList.add('scanning');
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Scanning...</span>';
        }

        if (progressBar) progressBar.style.display = 'block';
        if (progressText) progressText.style.display = 'block';
        if (breachResults) {
            breachResults.innerHTML = '';
            breachResults.classList.remove('active');
        }

        try {
            // Perform real breach detection
            this.updateScanProgress(0, 'Initializing security scan...');
            await this.delay(500);
            
            this.updateScanProgress(10, 'Connecting to Have I Been Pwned...');
            await this.delay(500);
            
            // Generate real breach data
            this.breachData = await this.generateRealBreachData();
            
            this.updateScanProgress(100, 'Finalizing security report...');
            await this.delay(500);
            
        } catch (error) {
            console.error('Scan error:', error);
            this.updateScanProgress(100, 'Scan completed with errors');
        }
        this.completeScan();
    }

    completeScan() {
        this.isScanning = false;

        const scanBtn = document.getElementById('scanBtn');
        const rescanBtn = document.getElementById('rescanBtn');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');

        // Hide progress
        if (progressBar) progressBar.style.display = 'none';
        if (progressText) progressText.style.display = 'none';

        // Update buttons
        if (scanBtn) {
            scanBtn.classList.remove('scanning');
            scanBtn.style.display = 'none';
        }
        if (rescanBtn) {
            rescanBtn.style.display = 'inline-flex';
        }
        this.updateStats();
        this.displayResults();

        // Save results to localStorage
        localStorage.setItem('breachScanResults', JSON.stringify(this.breachData));
        localStorage.setItem('lastScanDate', new Date().toISOString());

        // Show completion notification
        const breachedCount = this.breachData.filter(item => item.status === 'danger').length;
        if (breachedCount > 0) {
            this.showNotification(`Scan complete: ${breachedCount} breached passwords found!`, 'error');
        } else {
            this.showNotification('Scan complete: No breached passwords detected!', 'success');
        }
    }

    displayResults() {
        const breachResults = document.getElementById('breachResults');
        if (!breachResults) return;

        breachResults.innerHTML = '';
        
        // Sort results by risk level
        const sortedResults = [...this.breachData].sort((a, b) => {
            const riskOrder = { 'danger': 0, 'warning': 1, 'safe': 2 };
            return riskOrder[a.status] - riskOrder[b.status];
        });

        sortedResults.forEach(item => {
            const resultCard = document.createElement('div');
            resultCard.className = `breach-result-card ${item.status}`;
            
            const statusText = {
                'safe': 'Secure',
                'warning': 'At Risk',
                'danger': 'Breached'
            };

            const statusIcon = {
                'safe': 'fas fa-check-circle',
                'warning': 'fas fa-exclamation-triangle',
                'danger': 'fas fa-skull-crossbones'
            };

            // Additional details for breach information
            let additionalInfo = '';
            if (item.passwordBreached) {
                additionalInfo += `<br><strong>Password seen in breaches:</strong> ${item.passwordBreachCount.toLocaleString()} times`;
            }
            if (item.emailBreached && item.emailBreaches.length > 0) {
                const breachNames = item.emailBreaches.slice(0, 2).map(b => b.Name).join(', ');
                additionalInfo += `<br><strong>Email found in:</strong> ${breachNames}${item.emailBreaches.length > 2 ? ` and ${item.emailBreaches.length - 2} others` : ''}`;
            }

            resultCard.innerHTML = `
                <div class="breach-result-header">
                    <div class="breach-service-name">
                        <i class="${statusIcon[item.status]}" style="margin-right: 0.5rem;"></i>
                        ${item.serviceName}
                    </div>
                    <div class="breach-status ${item.status}">
                        ${statusText[item.status]}
                    </div>
                </div>
                <div class="breach-details">
                    <strong>Account:</strong> ${item.username}<br>
                    <strong>Status:</strong> ${item.details}${additionalInfo}<br>
                    <strong>Last Checked:</strong> ${new Date(item.lastChecked).toLocaleString()}
                </div>
            `;

            breachResults.appendChild(resultCard);
        });

        breachResults.classList.add('active');
    }

    showNotification(message, type = 'success') {
        // Create temporary notification
        const notification = document.createElement('div');
        const bgColor = type === 'error' ? '#dc3545' : '#28a745';
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${bgColor};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1001;
            animation: slideIn 0.3s ease;
            max-width: 300px;
        `;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.4s ease';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Enhanced BreachUtils with real HIBP integration
const BreachUtils = {
    // Enhanced password strength checking
    checkPasswordStrength(password) {
        let score = 0;
        const checks = {
            length: password.length >= 8,
            longLength: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /\d/.test(password),
            symbols: /[!@#$%^&*(),.?":{}|<>]/.test(password),
            notCommon: !this.isCommonPassword(password)
        };

        Object.values(checks).forEach(check => {
            if (check) score++;
        });

        if (score < 4) return 'weak';
        if (score < 6) return 'medium';
        return 'strong';
    },

    // Enhanced common password check
    isCommonPassword(password) {
        const commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'password1', '123123', 'welcome123', 'sunshine',
            'princess', 'azerty', 'trustno1', 'football'
        ];
        return commonPasswords.includes(password.toLowerCase());
    },

    // Real breach database lookup using HIBP
    async checkAgainstBreaches(password) {
        try {
            const breachDetection = new BreachDetection();
            const result = await breachDetection.checkPasswordBreaches(password);
            
            if (result === null) {
                return {
                    error: true,
                    message: 'Unable to check against breach database'
                };
            }
            
            return result;
        } catch (error) {
            console.error('Error checking breaches:', error);
            return {
                error: true,
                message: error.message
            };
        }
    },

    // Generate security recommendations based on real breach data
    generateRecommendations(breachData) {
        const recommendations = [];
        
        const breachedCount = breachData.filter(item => item.status === 'danger').length;
        const warningCount = breachData.filter(item => item.status === 'warning').length;
        const totalPasswords = breachData.length;
        
        if (breachedCount > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Change Breached Passwords Immediately',
                description: `${breachedCount} of your passwords have been found in data breaches. These should be changed immediately to prevent account compromise.`,
                action: 'Change passwords now',
                count: breachedCount
            });
        }
        
        if (warningCount > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Review At-Risk Accounts',
                description: `${warningCount} accounts may be at risk due to weak passwords or email breaches. Consider strengthening these passwords.`,
                action: 'Review and strengthen',
                count: warningCount
            });
        }
        
        recommendations.push({
            priority: 'medium',
            title: 'Enable Two-Factor Authentication',
            description: 'Add an extra layer of security to your most important accounts.',
            action: 'Enable 2FA'
        });
        
        if (totalPasswords < 10) {
            recommendations.push({
                priority: 'low',
                title: 'Add More Accounts to Monitor',
                description: 'Consider adding more accounts to your password manager for comprehensive security monitoring.',
                action: 'Add accounts'
            });
        }
        
        return recommendations;
    }
};
        // Application State
        let passwords = [];
        let currentEditId = null;
        let isVaultUnlocked = false;
        let masterPassword = ''; // Will be set when user enters master password

        // Initialize app
        document.addEventListener('DOMContentLoaded', function() {
            const breachDetection = new BreachDetection();
    
    // Make it globally accessible
            window.breachDetection = breachDetection;
            window.BreachUtils = BreachUtils;
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
 