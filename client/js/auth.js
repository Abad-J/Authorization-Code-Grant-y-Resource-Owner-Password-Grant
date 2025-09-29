class OAuthClient {
    constructor(config) {
        this.config = config;
        this.accessToken = localStorage.getItem('oauth_access_token');
        this.refreshToken = localStorage.getItem('oauth_refresh_token');
        this.grantType = localStorage.getItem('oauth_grant_type') || 'authorization_code';
    }

    // ========== AUTHORIZATION CODE GRANT ==========
    
    initiateAuth() {
        const state = this.generateRandomString();
        const codeVerifier = this.generateRandomString();
        const codeChallenge = this.base64URLEncode(
            this.sha256(codeVerifier)
        );

        localStorage.setItem('oauth_state', state);
        localStorage.setItem('oauth_code_verifier', codeVerifier);

        const authUrl = new URL(this.config.authorizationEndpoint);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('client_id', this.config.clientId);
        authUrl.searchParams.set('redirect_uri', this.config.redirectUri);
        authUrl.searchParams.set('scope', this.config.scope);
        authUrl.searchParams.set('state', state);
        authUrl.searchParams.set('code_challenge', codeChallenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');

        window.location.href = authUrl.toString();
    }

    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');

        if (error) {
            throw new Error(`Error de autorización: ${error}`);
        }

        const savedState = localStorage.getItem('oauth_state');
        if (state !== savedState) {
            throw new Error('State no coincide - posible ataque CSRF');
        }

        const codeVerifier = localStorage.getItem('oauth_code_verifier');
        
        try {
            const tokens = await this.exchangeCodeForToken(code, codeVerifier);
            this.setTokens(tokens, 'authorization_code');
            
            localStorage.removeItem('oauth_state');
            localStorage.removeItem('oauth_code_verifier');
            
            return tokens;
        } catch (error) {
            throw new Error(`Error intercambiando código: ${error.message}`);
        }
    }

    async exchangeCodeForToken(code, codeVerifier) {
        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                redirect_uri: this.config.redirectUri,
                code: code,
                code_verifier: codeVerifier
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Error del servidor: ${response.status} - ${errorText}`);
        }

        return await response.json();
    }

    // ========== RESOURCE OWNER PASSWORD CREDENTIALS ==========
    
    async loginWithPassword(username, password) {
        if (!this.config.enablePasswordGrant) {
            throw new Error('Password Grant no está habilitado');
        }

        try {
            const tokens = await this.exchangePasswordForToken(username, password);
            this.setTokens(tokens, 'password');
            return tokens;
        } catch (error) {
            throw new Error(`Error en login con password: ${error.message}`);
        }
    }

    async exchangePasswordForToken(username, password) {
        const response = await fetch(this.config.passwordGrantEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'password',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                username: username,
                password: password,
                scope: this.config.scope
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Error desconocido' }));
            throw new Error(`Error de autenticación: ${errorData.error || response.status}`);
        }

        return await response.json();
    }

    // ========== MÉTODOS COMUNES ==========
    
    setTokens(tokens, grantType) {
        this.accessToken = tokens.access_token;
        this.refreshToken = tokens.refresh_token;
        this.grantType = grantType;
        
        localStorage.setItem('oauth_access_token', this.accessToken);
        localStorage.setItem('oauth_grant_type', this.grantType);
        
        if (this.refreshToken) {
            localStorage.setItem('oauth_refresh_token', this.refreshToken);
        }
    }

    async getUserInfo() {
        return await this.callAPI(this.config.userInfoEndpoint);
    }

    async callAPI(endpoint, options = {}) {
        if (!this.accessToken) {
            throw new Error('No hay token de acceso disponible');
        }

        const defaultOptions = {
            headers: {
                'Authorization': `Bearer ${this.accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const response = await fetch(endpoint, {
            ...defaultOptions,
            ...options
        });

        if (response.status === 401) {
            await this.refreshAccessToken();
            return this.callAPI(endpoint, options);
        }

        if (!response.ok) {
            throw new Error(`Error API: ${response.status} - ${await response.text()}`);
        }

        return await response.json();
    }

    async refreshAccessToken() {
        if (!this.refreshToken) {
            throw new Error('No hay refresh token disponible');
        }

        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                refresh_token: this.refreshToken
            })
        });

        if (!response.ok) {
            this.logout();
            throw new Error('Error refrescando token - sesión expirada');
        }

        const tokens = await response.json();
        this.setTokens(tokens, this.grantType);
        
        return tokens;
    }

    isAuthenticated() {
        return !!this.accessToken;
    }

    getGrantType() {
        return this.grantType;
    }

    logout() {
        this.accessToken = null;
        this.refreshToken = null;
        this.grantType = 'authorization_code';
        
        localStorage.removeItem('oauth_access_token');
        localStorage.removeItem('oauth_refresh_token');
        localStorage.removeItem('oauth_grant_type');
    }

    // Utilidades
    generateRandomString() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    base64URLEncode(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    async sha256(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return hash;
    }
}