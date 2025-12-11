// static/js/auth.js

// Function to handle Google Login
function handleGoogleLogin(event) {
    event.preventDefault();
    // Redirect the user to the Google OAuth callback route
    window.location.href = '/auth/google/callback';
}

// Initialize authentication event listeners
function initializeAuth() {
    const googleButtons = document.querySelectorAll('.google-button');

    googleButtons.forEach(button => {
        button.addEventListener('click', handleGoogleLogin);
    });
}

// Initialize when DOM is fully loaded
document.addEventListener('DOMContentLoaded', initializeAuth);
