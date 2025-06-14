
        // Mobile menu toggle
        const mobileMenu = document.getElementById('mobileMenu');
        const mobileNav = document.querySelector('.mobile-nav');
        
        mobileMenu.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
            mobileNav.classList.toggle('active');
        });

        // Close mobile menu when clicking a link
        mobileNav.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                mobileMenu.classList.remove('active');
                mobileNav.classList.remove('active');
            });
        });

        // Scroll animations
        const animateOnScroll = () => {
            const elements = document.querySelectorAll('.scroll-animate');
            
            elements.forEach(element => {
                const elementPosition = element.getBoundingClientRect().top;
                const screenPosition = window.innerHeight / 1.2;
                
                if (elementPosition < screenPosition) {
                    element.classList.add('animate');
                }
            });
        };

        // Initialize scroll animations
        window.addEventListener('load', animateOnScroll);
        window.addEventListener('scroll', animateOnScroll);

        // Animate stats
        const animateStats = () => {
            const statItems = document.querySelectorAll('.stat-item[data-target]');
            
            statItems.forEach(item => {
                const target = parseInt(item.getAttribute('data-target'));
                const suffix = item.getAttribute('data-suffix') || '';
                const duration = 2000;
                const start = 0;
                const increment = target / (duration / 16);
                let current = start;
                
                const timer = setInterval(() => {
                    current += increment;
                    if (current >= target) {
                        clearInterval(timer);
                        current = target;
                    }
                    
                    item.querySelector('.stat-number').textContent = 
                        Number.isInteger(target) ? Math.floor(current) + suffix : current.toFixed(1) + suffix;
                }, 16);
            });
        };

        // Intersection Observer for stats animation
        const statsObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateStats();
                    statsObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        document.querySelectorAll('.stats-grid').forEach(grid => {
            statsObserver.observe(grid);
        });

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    window.scrollTo({
                        top: targetElement.offsetTop - 80,
                        behavior: 'smooth'
                    });
                }
            });
        });

        // Navbar scroll effect
        window.addEventListener('scroll', () => {
            const navbar = document.getElementById('navbar');
            if (window.scrollY > 50) {
                navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';
            } else {
                navbar.style.boxShadow = 'none';
            }
        });
