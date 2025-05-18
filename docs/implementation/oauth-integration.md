# OAuth Integration Guide

This guide provides detailed instructions for integrating OAuth 2.0 with ETDI.

## Overview

ETDI uses OAuth 2.0 to provide:
- Centralized identity management
- Fine-grained permission control
- Token-based authentication
- Scope-based authorization

## Supported OAuth Providers

1. Auth0
2. Okta
3. Azure AD
4. Custom OAuth 2.0 providers

## Implementation Steps

### 1. Provider Configuration

```typescript
import { OAuthConfig } from '@etdi/oauth';

const config: OAuthConfig = {
  provider: 'auth0', // or 'okta', 'azure', 'custom'
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  domain: 'your-domain',
  audience: 'your-audience',
  scopes: ['openid', 'profile', 'email']
};
```

### 2. OAuth Manager Setup

```typescript
import { OAuthManager } from '@etdi/oauth';

const oauthManager = new OAuthManager(config);

// Initialize the manager
await oauthManager.initialize();
```

### 3. Token Management

```typescript
// Request token
const token = await oauthManager.getToken();

// Validate token
const isValid = await oauthManager.validateToken(token);

// Refresh token
const newToken = await oauthManager.refreshToken(token);
```

### 4. Scope Management

```typescript
// Define required scopes
const requiredScopes = ['read:tools', 'write:tools'];

// Check scope availability
const hasScopes = await oauthManager.hasScopes(requiredScopes);

// Request additional scopes
const newToken = await oauthManager.requestScopes(requiredScopes);
```

### 5. Integration with ETDI Client

```typescript
import { ETDIClient } from '@etdi/sdk';

const client = new ETDIClient({
  oauthManager,
  securityLevel: 'enhanced'
});
```

## Provider-Specific Configuration

### Auth0

```typescript
const auth0Config = {
  provider: 'auth0',
  clientId: 'your-auth0-client-id',
  clientSecret: 'your-auth0-client-secret',
  domain: 'your-auth0-domain',
  audience: 'your-api-identifier',
  scopes: ['openid', 'profile', 'email']
};
```

### Okta

```typescript
const oktaConfig = {
  provider: 'okta',
  clientId: 'your-okta-client-id',
  clientSecret: 'your-okta-client-secret',
  domain: 'your-okta-domain',
  audience: 'your-api-identifier',
  scopes: ['openid', 'profile', 'email']
};
```

### Azure AD

```typescript
const azureConfig = {
  provider: 'azure',
  clientId: 'your-azure-client-id',
  clientSecret: 'your-azure-client-secret',
  tenantId: 'your-azure-tenant-id',
  audience: 'your-api-identifier',
  scopes: ['openid', 'profile', 'email']
};
```

## Security Considerations

### 1. Token Storage

- Store tokens securely
- Use secure storage mechanisms
- Implement token rotation
- Handle token expiration

### 2. Scope Management

- Request minimum required scopes
- Validate scope changes
- Monitor scope usage
- Implement scope revocation

### 3. Error Handling

```typescript
try {
  await oauthManager.getToken();
} catch (error) {
  if (error.isTokenExpired) {
    // Handle token expiration
  } else if (error.isScopeError) {
    // Handle scope errors
  } else {
    // Handle other errors
  }
}
```

## Best Practices

1. **Token Management**
   - Implement token refresh
   - Handle token expiration
   - Secure token storage
   - Monitor token usage

2. **Scope Management**
   - Use least privilege principle
   - Validate scope changes
   - Monitor scope usage
   - Implement scope revocation

3. **Error Handling**
   - Implement proper error handling
   - Log security events
   - Monitor for suspicious activity
   - Implement retry mechanisms

4. **Security**
   - Use HTTPS
   - Implement proper validation
   - Monitor for security events
   - Regular security reviews

## Troubleshooting

### Common Issues

1. **Token Issues**
   - Token expiration
   - Invalid tokens
   - Scope mismatches
   - Provider errors

2. **Configuration Issues**
   - Invalid credentials
   - Incorrect scopes
   - Provider misconfiguration
   - Network issues

3. **Integration Issues**
   - Client misconfiguration
   - Provider compatibility
   - Scope validation
   - Token validation

## Support

For additional help:
- Check the [API Reference](../development/api-reference.md)
- Review the [Examples](../development/examples.md)
- Join our [Community Forum](https://community.etdi.io)
- Submit an [Issue](https://github.com/etdi/issues) 