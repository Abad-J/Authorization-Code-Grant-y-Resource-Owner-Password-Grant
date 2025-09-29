// Configuración de OAuth
const config = {
    // Authorization Code Grant
    clientId: 'tu-client-id',
    clientSecret: 'tu-client-secret',
    authorizationEndpoint: 'http://localhost:3001/authorize',
    tokenEndpoint: 'http://localhost:3001/token',
    redirectUri: 'http://localhost:3001/callback.html',
    userInfoEndpoint: 'http://localhost:3001/api/userinfo',
    scope: 'profile email',
    
    // Resource Owner Password Credentials
    enablePasswordGrant: true,
    passwordGrantEndpoint: 'http://localhost:3001/oauth/token'
};