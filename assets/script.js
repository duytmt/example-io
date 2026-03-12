document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.tool-card');

    // Premium Spotlight Effect for Cards
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });

    // Premium "Antigravity" Particle Trail
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    document.body.appendChild(canvas);

    Object.assign(canvas.style, {
        position: 'fixed',
        top: '0',
        left: '0',
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: '9999',
        mixBlendMode: 'screen' // Adds a glowing effect
    });

    let width, height;
    let particles = [];

    // Antigravity palette
    const colors = ['#8ab4f8', '#c58af9', '#f0ebf8', '#4285f4'];

    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    // Mouse state
    const mouse = { x: -100, y: -100 };
    document.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;

        // Emit particles on move
        for (let i = 0; i < 2; i++) {
            particles.push(new Particle(mouse.x, mouse.y));
        }
    });

    class Particle {
        constructor(x, y) {
            this.x = x;
            this.y = y;
            // Random scatter
            this.vx = (Math.random() - 0.5) * 1.5;
            this.vy = (Math.random() - 0.5) * 1.5;
            this.size = Math.random() * 2 + 0.5;
            this.life = 1; // 100% opacity
            this.decay = 0.015 + Math.random() * 0.02;
            this.color = colors[Math.floor(Math.random() * colors.length)];
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;
            this.life -= this.decay;
        }

        draw() {
            ctx.globalAlpha = this.life;
            ctx.fillStyle = this.color;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        // Soft trail effect (uncomment to make trails linger longer visually)
        // ctx.fillStyle = 'rgba(0, 0, 0, 0.1)';
        // ctx.fillRect(0, 0, width, height);

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.update();
            p.draw();

            if (p.life <= 0) {
                particles.splice(i, 1);
                i--;
            }
        }

        // Draw connection lines for "tech" feel (Constellation effect near mouse)
        // Only connect particles close to each other
        ctx.globalAlpha = 0.15;
        ctx.strokeStyle = '#8ab4f8';
        ctx.lineWidth = 0.5;

        for (let i = 0; i < particles.length; i++) {
            const p1 = particles[i];
            // Connect to mouse if close
            const dx = mouse.x - p1.x;
            const dy = mouse.y - p1.y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 100) {
                ctx.beginPath();
                ctx.moveTo(p1.x, p1.y);
                ctx.lineTo(mouse.x, mouse.y);
                ctx.stroke();
            }
        }

        requestAnimationFrame(animate);
    }
    animate();
});
