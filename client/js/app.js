// Instancia el cliente OAuth
const oauthClient = new OAuthClient(config);

// Inicializa la aplicación cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Verifica el tipo de página actual
    if (window.location.pathname.endsWith('callback.html')) {
        handleCallbackPage();
        return;
    }
    
    if (window.location.pathname.endsWith('login.html')) {
        handleLoginPage();
        return;
    }

    // Página principal
    setupEventListeners();
    checkAuthStatus();
}

function setupEventListeners() {
    const loginBtn = document.getElementById('loginBtn');
    const passwordLoginBtn = document.getElementById('passwordLoginBtn');
    const apiBtn = document.getElementById('apiBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    if (loginBtn) loginBtn.addEventListener('click', handleAuthorizationCodeLogin);
    if (passwordLoginBtn) passwordLoginBtn.addEventListener('click', redirectToPasswordLogin);
    if (apiBtn) apiBtn.addEventListener('click', handleApiCall);
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
}

// ========== AUTHORIZATION CODE GRANT ==========

async function handleAuthorizationCodeLogin() {
    try {
        setStatus('Iniciando flujo de Authorization Code...', 'loading');
        oauthClient.initiateAuth();
    } catch (error) {
        setStatus(`Error: ${error.message}`, 'error');
    }
}

function redirectToPasswordLogin() {
    window.location.href = 'login.html';
}

// ========== PASSWORD GRANT ==========

function handleLoginPage() {
    const loginForm = document.getElementById('passwordLoginForm');
    const backBtn = document.getElementById('backBtn');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handlePasswordLogin);
    }
    
    if (backBtn) {
        backBtn.addEventListener('click', () => {
            window.location.href = 'index.html';
        });
    }
    
    // Verifica si ya está autenticado
    if (oauthClient.isAuthenticated()) {
        window.location.href = 'index.html';
    }
}

async function handlePasswordLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const statusDiv = document.getElementById('status');
    
    if (!username || !password) {
        setStatus('Por favor ingresa usuario y contraseña', 'error');
        return;
    }
    
    try {
        setStatus('Iniciando sesión...', 'loading');
        await oauthClient.loginWithPassword(username, password);
        setStatus('¡Login exitoso! Redirigiendo...', 'success');
        
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 1500);
        
    } catch (error) {
        setStatus(`Error: ${error.message}`, 'error');
    }
}

// ========== MÉTODOS COMUNES ==========

async function handleApiCall() {
    try {
        setStatus('Llamando a la API...', 'loading');
        const userInfo = await oauthClient.getUserInfo();
        displayUserInfo(userInfo);
        setStatus('¡Llamada a API exitosa!', 'success');
    } catch (error) {
        setStatus(`Error: ${error.message}`, 'error');
    }
}

function handleLogout() {
    oauthClient.logout();
    setStatus('Sesión cerrada correctamente', 'success');
    hideUserInfo();
    checkAuthStatus();
}

function checkAuthStatus() {
    const loginBtn = document.getElementById('loginBtn');
    const passwordLoginBtn = document.getElementById('passwordLoginBtn');
    const apiBtn = document.getElementById('apiBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const grantTypeSpan = document.getElementById('grantType');

    if (oauthClient.isAuthenticated()) {
        const grantType = oauthClient.getGrantType();
        setStatus(`Autenticado correctamente (${grantType})`, 'success');
        
        if (loginBtn) loginBtn.disabled = true;
        if (passwordLoginBtn) passwordLoginBtn.disabled = true;
        if (apiBtn) apiBtn.disabled = false;
        if (logoutBtn) logoutBtn.disabled = false;
        if (grantTypeSpan) grantTypeSpan.textContent = grantType;
    } else {
        setStatus('No autenticado', 'error');
        if (loginBtn) loginBtn.disabled = false;
        if (passwordLoginBtn) passwordLoginBtn.disabled = false;
        if (apiBtn) apiBtn.disabled = true;
        if (logoutBtn) logoutBtn.disabled = true;
        if (grantTypeSpan) grantTypeSpan.textContent = 'N/A';
    }
}

function setStatus(message, type = '') {
    const statusDiv = document.getElementById('status');
    if (statusDiv) {
        statusDiv.innerHTML = `<p class="${type}">${message}</p>`;
    }
}

function displayUserInfo(userInfo) {
    const userInfoDiv = document.getElementById('userInfo');
    const userDataDiv = document.getElementById('userData');
    
    if (userDataDiv) {
        userDataDiv.innerHTML = `
            <pre>${JSON.stringify(userInfo, null, 2)}</pre>
        `;
    }
    if (userInfoDiv) {
        userInfoDiv.style.display = 'block';
    }
}

function hideUserInfo() {
    const userInfoDiv = document.getElementById('userInfo');
    if (userInfoDiv) {
        userInfoDiv.style.display = 'none';
    }
}

// Maneja la página de callback
async function handleCallbackPage() {
    try {
        setStatus('Procesando autorización...', 'loading');
        await oauthClient.handleCallback();
        setStatus('¡Autenticación exitosa! Redirigiendo...', 'success');
        
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 2000);
        
    } catch (error) {
        setStatus(`Error en autenticación: ${error.message}`, 'error');
        
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 3000);
    }
}