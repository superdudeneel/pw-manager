
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            particlesContainer.style.opacity = '1';
            
            for (let i = 0; i < 12; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                
                const angle = (i * 30) * Math.PI / 180;
                const distance = 80 + Math.random() * 40;
                const x = Math.cos(angle) * distance;
                const y = Math.sin(angle) * distance;
                
                particle.style.setProperty('--x', x + 'px');
                particle.style.setProperty('--y', y + 'px');
                particle.style.left = '50%';
                particle.style.top = '50%';
                particle.style.transform = 'translate(-50%, -50%)';
                
                particlesContainer.appendChild(particle);
            }
            
            setTimeout(() => {
                particlesContainer.style.opacity = '0';
                particlesContainer.innerHTML = '';
            }, 2000);
        }

        // Show initial status
        document.getElementById('statusText').classList.add('show');

        // Simulate email sending process
        setTimeout(() => {
            // Hide loading ring
            document.getElementById('loadingRing').style.display = 'none';
            
            // Show checkmark
            document.getElementById('checkmark').style.display = 'flex';
            
            // Create particle effect
            createParticles();
            
            // Update text content
            setTimeout(() => {
                document.getElementById('title').textContent = 'Email Sent!';
                document.getElementById('message').textContent = 'Your message has been delivered successfully';
                document.getElementById('emailAddress').style.display = 'inline-block';
            }, 300);
            
        }, 2000);

        // Handle done button click
        document.getElementById('doneBtn').addEventListener('click', (e) => {
            e.preventDefault();
            // You can add navigation logic here
            window.location.href = '/login';
            
        });
