/**
 * 
 * Este servidor implementa un proveedor OAuth 2.0 básico que soporta
 * múltiples flujos de autorización
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();
// El servidor configura los middleware necesarios
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../client')));

// El sistema utiliza almacenamiento en memoria para simular una base de datos
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

// Base de datos Cuentas de prueba
const users = {
    'demo@ejemplo.com': {
        password: 'password123',
        id: 1,
        name: 'Usuario Demo',
        email: 'demo@ejemplo.com',
        email_verified: true
    },
    'test@ejemplo.com': {
        password: 'test123',
        id: 2,
        name: 'Usuario Test',
        email: 'test@ejemplo.com',
        email_verified: false
    }
};
//El registro de aplicaciones cliente autorizadas
const clients = {
    'tu-client-id': {
        clientSecret: 'tu-client-secret',
        redirectUris: ['http://localhost:3001/callback.html'],
        grants: ['authorization_code', 'password', 'refresh_token']
    }
};

// ========== AUTHORIZATION CODE GRANT ==========
/**
 * El servidor maneja solicitudes de autorización mostrando
 * una interfaz de consentimiento al usuario
 */
app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, state, code_challenge, scope } = req.query;

    if (!clients[client_id]) {
        return res.status(400).json({ error: 'invalid_client' });
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Autorización</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
                .container { border: 1px solid #ddd; padding: 20px; border-radius: 8px; text-align: center; }
                button { padding: 10px 20px; margin: 5px; cursor: pointer; font-size: 16px; }
                .allow { background: #4CAF50; color: white; border: none; }
                .deny { background: #f44336; color: white; border: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>¿Autorizar aplicación?</h2>
                <p>La aplicación solicita acceso a: <strong>${scope}</strong></p>
                <form method="post" action="/authorize">
                    <input type="hidden" name="client_id" value="${client_id}">
                    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
                    <input type="hidden" name="state" value="${state}">
                    <input type="hidden" name="code_challenge" value="${code_challenge}">
                    <button type="submit" name="action" value="allow" class="allow">Permitir</button>
                    <button type="submit" name="action" value="deny" class="deny">Denegar</button>
                </form>
            </div>
        </body>
        </html>
    `);
});
/**
 * El servidor procesa la respuesta del usuario a la solicitud de autorización
 */
app.post('/authorize', (req, res) => {
    const { client_id, redirect_uri, state, code_challenge, action } = req.body;
// Si el usuario deniega el acceso, el servidor redirige con error
    if (action === 'deny') {
        return res.redirect(`${redirect_uri}?error=access_denied&state=${state}`);
    }
// El sistema genera un código de autorización seguro
    const authCode = crypto.randomBytes(32).toString('hex');
// El servidor almacena el código con metadatos relevantes
    authCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        expiresAt: Date.now() + 10 * 60 * 1000
    });
// El sistema redirige a la URI especificada con el código
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    redirectUrl.searchParams.set('state', state);

    res.redirect(redirectUrl.toString());
});

// ========== TOKEN ENDPOINT ==========
/**
 * El endpoint de tokens maneja el intercambio de credenciales por tokens de acceso
 */
app.post('/token', async (req, res) => {
    const { grant_type, client_id, client_secret, code, redirect_uri, code_verifier, username, password, refresh_token } = req.body;

    const client = clients[client_id];
    if (!client || client.clientSecret !== client_secret) {
        return res.status(401).json({ error: 'invalid_client' });
    }
 // El servidor verifica que el tipo de grant sea soportado
    if (!client.grants.includes(grant_type)) {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    try {
        let tokens;
// El sistema delega el procesamiento según el tipo de grant
        switch (grant_type) {
            case 'authorization_code':
                tokens = await handleAuthorizationCodeGrant(code, code_verifier, client_id);
                break;
            case 'password':
                tokens = await handlePasswordGrant(username, password, client_id);
                break;
            case 'refresh_token':
                tokens = await handleRefreshTokenGrant(refresh_token, client_id);
                break;
            default:
                return res.status(400).json({ error: 'unsupported_grant_type' });
        }
 // El servidor retorna los tokens generados
        res.json(tokens);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * El manejador para el flujo Authorization Code Grant
 * Valida códigos de autorización y los intercambia por tokens
 */
async function handleAuthorizationCodeGrant(code, code_verifier, clientId) {
    const authCodeData = authCodes.get(code);
    if (!authCodeData) {
        throw new Error('invalid_grant');
    }
// El servidor verifica que el código no haya expirado
    if (Date.now() > authCodeData.expiresAt) {
        authCodes.delete(code);
        throw new Error('invalid_grant');
    }
// Si se proporciona un code_verifier, el sistema valida el challenge PKCE
    if (code_verifier) {
        const codeChallenge = base64URLEncode(
            crypto.createHash('sha256').update(code_verifier).digest()
        );
        
        if (codeChallenge !== authCodeData.codeChallenge) {
            throw new Error('invalid_grant');
        }
    }

    authCodes.delete(code);
    return generateTokens(clientId, 'authorization_code');
}
/**
 * El manejador para el flujo Password Grant
 * Autentica usuarios directamente con credenciales
 */
async function handlePasswordGrant(username, password, clientId) {
    if (!username || !password) {
        throw new Error('invalid_request');
    }

    const user = users[username];
    if (!user || user.password !== password) {
        throw new Error('invalid_grant');
    }

    return generateTokens(clientId, 'password', user);
}
/**
 * El manejador para el flujo Refresh Token Grant
 * Renueva tokens de acceso expirados
 */
async function handleRefreshTokenGrant(refresh_token, clientId) {
    const refreshData = refreshTokens.get(refresh_token);
    if (!refreshData || refreshData.clientId !== clientId) {
        throw new Error('invalid_grant');
    }

    accessTokens.delete(refreshData.accessToken);
    refreshTokens.delete(refresh_token);
    return generateTokens(clientId, 'refresh_token');
}
/**
 * La función generadora de tokens crea pares de access/refresh tokens
 * y los almacena en el sistema con sus metadatos
 */
function generateTokens(clientId, grantType, user = null) {
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');

    const tokenData = {
        clientId: clientId,
        grantType: grantType,
        scope: 'profile email',
        expiresAt: Date.now() + 60 * 60 * 1000,
        user: user ? { id: user.id, email: user.email } : null
    };

    accessTokens.set(accessToken, tokenData);
    refreshTokens.set(refreshToken, { clientId, accessToken });

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: 'profile email'
    };
}

// ========== API PROTEGIDA ==========
/**
 * El endpoint de información de usuario requiere autenticación
 * y retorna datos del perfil del usuario autenticado
 */
app.get('/api/userinfo', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'missing_authorization' });
    }

    const token = authHeader.substring(7);
    const tokenData = accessTokens.get(token);

    if (!tokenData) {
        return res.status(401).json({ error: 'invalid_token' });
    }

    if (Date.now() > tokenData.expiresAt) {
        accessTokens.delete(token);
        return res.status(401).json({ error: 'token_expired' });
    }

    let userInfo;
    if (tokenData.user) {
        userInfo = users[tokenData.user.email];
    } else {
        // Para tokens sin usuario específico, usa datos por defecto
        userInfo = {
            id: 12345,
            name: 'Usuario OAuth',
            email: 'usuario@oauth.com',
            email_verified: true
        };
    }
 // Retorna la información del usuario en formato estándar
    res.json({
        user_id: userInfo.id,
        name: userInfo.name,
        email: userInfo.email,
        email_verified: userInfo.email_verified,
        grant_type: tokenData.grantType,
        client_id: tokenData.clientId,
        scope: tokenData.scope
    });
});

// Endpoint específico para Password Grant
app.post('/oauth/token', (req, res) => {
    req.url = '/token';
    app.handle(req, res);
});

// ========== RUTAS PARA PÁGINAS ==========
// El sistema sirve las páginas HTML de la aplicación cliente
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/login.html'));
});

app.get('/callback.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/callback.html'));
});

// Función de utilidad
function base64URLEncode(buffer) {
    return buffer.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

// Iniciar servidor
/**
 * El servidor inicia y se pone a escuchar en el puerto 3001
 * mostrando información de configuración en la consola
 */
app.listen(3001, () => {
    console.log('🚀 Servidor OAuth ejecutándose en http://localhost:3001');
    console.log('📧 Credenciales de demo:');
    console.log('   Usuario: demo@ejemplo.com');
    console.log('   Contraseña: password123');
    console.log('   Usuario: test@ejemplo.com');
    console.log('   Contraseña: test123');
});