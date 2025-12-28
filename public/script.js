function loadinganimation() {
  // Only run loading animation on desktop
  if (window.innerWidth > 768) {
    gsap.from("#head,#head1,.pera1", {
      y: 30,
      opacity: 0,
      delay: 0.3,
      duration: 0.8,
      stagger: 0.2,
      ease: "power2.out"
    });
    
    gsap.from("nav", {
      y: -20,
      opacity: 0,
      delay: 0.1,
      duration: 0.5,
      ease: "power2.out"
    });
  } else {
    // Mobile: Simple fade in
    document.querySelectorAll("#head, #head1, .pera1").forEach(el => {
      el.style.opacity = '1';
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadinganimation();
  
  // Create background animation for all devices (optimized for mobile)
  createIndustrialBackground();
});

// Industrial Pipe Background Animation - Optimized for both desktop and mobile
function createIndustrialBackground() {
  const pipesContainer = document.querySelector('.pipes-container');
  const particlesContainer = document.querySelector('.particles-container');
  
  if (!pipesContainer || !particlesContainer) return;
  
  // Clear existing elements
  pipesContainer.innerHTML = '';
  particlesContainer.innerHTML = '';
  
  const colors = ['rgba(58, 123, 213, 0.1)', 'rgba(65, 131, 215, 0.15)', 'rgba(72, 139, 217, 0.2)'];
  const isMobile = window.innerWidth <= 768;
  
  // Create pipes - fewer and smaller on mobile
  const pipeCount = isMobile ? 3 : 6;
  for (let i = 0; i < pipeCount; i++) {
    const pipe = document.createElement('div');
    pipe.className = 'pipe';
    pipesContainer.appendChild(pipe);
    
    const isVertical = Math.random() > 0.5;
    const duration = isMobile ? gsap.utils.random(60, 80) : gsap.utils.random(40, 60);
    const size = isMobile ? gsap.utils.random(4, 12) : gsap.utils.random(8, 20);
    const length = isMobile ? gsap.utils.random(100, 200) : gsap.utils.random(150, 300);
    
    gsap.set(pipe, {
      width: isVertical ? `${size}px` : `${length}px`,
      height: isVertical ? `${length}px` : `${size}px`,
      background: colors[Math.floor(Math.random() * colors.length)],
      x: isVertical ? gsap.utils.random(0, window.innerWidth) : -length,
      y: isVertical ? -length : gsap.utils.random(0, window.innerHeight)
    });
    
    gsap.to(pipe, {
      x: isVertical ? gsap.utils.random(0, window.innerWidth) : window.innerWidth + length,
      y: isVertical ? window.innerHeight + length : gsap.utils.random(0, window.innerHeight),
      duration: duration,
      ease: "none",
      repeat: -1
    });
  }
  
  // Create pipe connectors - fewer on mobile
  const connectorCount = isMobile ? 6 : 10;
  for (let i = 0; i < connectorCount; i++) {
    const connector = document.createElement('div');
    connector.className = 'pipe-connector';
    pipesContainer.appendChild(connector);
    
    const size = isMobile ? gsap.utils.random(8, 20) : gsap.utils.random(12, 30);
    
    gsap.set(connector, {
      width: `${size}px`,
      height: `${size}px`,
      x: gsap.utils.random(0, window.innerWidth),
      y: gsap.utils.random(0, window.innerHeight),
      opacity: 0
    });
    
    gsap.to(connector, {
      opacity: isMobile ? 0.15 : 0.2,
      duration: gsap.utils.random(5, 10),
      yoyo: true,
      repeat: -1,
      delay: gsap.utils.random(0, 4)
    });
  }
  
  // Create floating particles (weld sparks) - fewer and slower on mobile
  const particleCount = isMobile ? 5 : 15;
  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particlesContainer.appendChild(particle);
    
    const size = isMobile ? gsap.utils.random(1, 3) : gsap.utils.random(2, 4);
    
    gsap.set(particle, {
      width: `${size}px`,
      height: `${size}px`,
      x: gsap.utils.random(0, window.innerWidth),
      y: gsap.utils.random(0, window.innerHeight),
      opacity: 0
    });
    
    // Spark animation - slower on mobile
    const moveDistance = isMobile ? 30 : 40;
    const tl = gsap.timeline({ 
      repeat: -1, 
      delay: gsap.utils.random(0, 8) 
    });
    
    tl.to(particle, {
      opacity: isMobile ? 0.4 : 0.6,
      duration: 0.5,
      ease: "power1.out"
    })
    .to(particle, {
      x: `+=${moveDistance}`,
      y: `+=${moveDistance}`,
      duration: isMobile ? 1.5 : 1.2,
      ease: "power1.inOut"
    })
    .to(particle, {
      opacity: 0,
      duration: 0.5,
      ease: "power1.in"
    });
  }
}

// Make background responsive to window resize
let resizeTimeout;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimeout);
  resizeTimeout = setTimeout(() => {
    // Recreate background on resize (optimized for current device)
    createIndustrialBackground();
  }, 300);
});