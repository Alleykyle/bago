class GlobalThemeManager {
  constructor() {
    this.currentTheme = 'light';
    this.currentFontSize = 'medium';
    this.currentAnimationSpeed = 'normal';
    this.init();
  }

  init() {
    // Load saved preferences on every page load
    this.loadPreferences();
    // Apply saved theme immediately
    this.applyTheme(this.currentTheme);
    this.applyFontSize(this.currentFontSize);
    this.applyAnimationSpeed(this.currentAnimationSpeed);
    // Listen for system theme changes
    this.watchSystemTheme();
  }

  loadPreferences() {
    this.currentTheme = localStorage.getItem('theme') || 'light';
    this.currentFontSize = localStorage.getItem('fontSize') || 'medium';
    this.currentAnimationSpeed = localStorage.getItem('animationSpeed') || 'normal';
  }

  applyTheme(theme) {
    const html = document.documentElement;
    
    // Add transition class for smooth theme switching
    html.classList.add('theme-transition');
    
    // Set theme attribute
    html.setAttribute('data-theme', theme);
    
    // Store current theme
    this.currentTheme = theme;
    localStorage.setItem('theme', theme);

    // Remove transition class after animation
    setTimeout(() => {
      html.classList.remove('theme-transition');
    }, 300);

    // Update theme selector if it exists on the page
    const themeSelector = document.getElementById('change-theme');
    if (themeSelector) {
      themeSelector.value = theme;
    }
  }

  applyFontSize(size) {
    const root = document.documentElement;
    const sizeMap = {
      'small': '12px',
      'medium': '14px',
      'large': '15px'
    };
    
    root.style.fontSize = sizeMap[size];
    this.currentFontSize = size;
    localStorage.setItem('fontSize', size);

    // Update font size selector if it exists
    const fontSizeSelector = document.getElementById('font-size');
    if (fontSizeSelector) {
      fontSizeSelector.value = size;
    }
  }

  applyAnimationSpeed(speed) {
    const root = document.documentElement;
    const speedMap = {
      'slow': '0.6s',
      'normal': '0.3s',
      'fast': '0.15s',
      'none': '0s'
    };
    
    root.style.setProperty('--transition-duration', speedMap[speed]);
    this.currentAnimationSpeed = speed;
    localStorage.setItem('animationSpeed', speed);

    // Update all transition durations
    const style = document.createElement('style');
    style.textContent = `
      .theme-transition * {
        transition-duration: ${speedMap[speed]} !important;
      }
    `;
    
    // Remove previous speed style if exists
    const oldStyle = document.getElementById('animation-speed-style');
    if (oldStyle) oldStyle.remove();
    
    style.id = 'animation-speed-style';
    document.head.appendChild(style);

    // Update animation speed selector if it exists
    const animationSpeedSelector = document.getElementById('animation-speed');
    if (animationSpeedSelector) {
      animationSpeedSelector.value = speed;
    }
  }

  watchSystemTheme() {
    if (window.matchMedia) {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      mediaQuery.addListener((e) => {
        if (this.currentTheme === 'auto') {
          // Force re-application of auto theme
          this.applyTheme('auto');
        }
      });
    }
  }

  // Method to change theme programmatically
  setTheme(theme) {
    this.applyTheme(theme);
  }

  // Method to get current theme
  getTheme() {
    return this.currentTheme;
  }

  // Method to toggle between light and dark
  toggleTheme() {
    const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
    this.applyTheme(newTheme);
    return newTheme;
  }
}

// Initialize global theme manager
let globalThemeManager;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  globalThemeManager = new GlobalThemeManager();
  
  // Add event listeners if theme controls exist on current page
  const themeSelector = document.getElementById('change-theme');
  if (themeSelector) {
    themeSelector.addEventListener('change', function(e) {
      globalThemeManager.setTheme(e.target.value);
    });
  }

  const fontSizeSelector = document.getElementById('font-size');
  if (fontSizeSelector) {
    fontSizeSelector.addEventListener('change', function(e) {
      globalThemeManager.applyFontSize(e.target.value);
    });
  }

  const animationSpeedSelector = document.getElementById('animation-speed');
  if (animationSpeedSelector) {
    animationSpeedSelector.addEventListener('change', function(e) {
      globalThemeManager.applyAnimationSpeed(e.target.value);
    });
  }
});

// Make theme manager globally accessible
window.globalThemeManager = globalThemeManager;