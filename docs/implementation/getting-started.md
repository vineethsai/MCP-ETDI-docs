# Getting Started with ETDI

This guide will help you get started with implementing ETDI in your application.

## Prerequisites

- Node.js 16.x or later
- TypeScript 4.x or later
- npm or yarn package manager
- Basic understanding of OAuth 2.0

## Installation

1. Install the ETDI SDK:

```bash
npm install @etdi/sdk
# or
yarn add @etdi/sdk
```

2. Install required dependencies:

```bash
npm install @etdi/oauth @etdi/crypto
# or
yarn add @etdi/oauth @etdi/crypto
```

## Basic Implementation

### 1. Initialize ETDI Client

```typescript
import { ETDIClient } from '@etdi/sdk';

const client = new ETDIClient({
  securityLevel: 'enhanced', // 'basic', 'enhanced', or 'strict'
  oauthConfig: {
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain'
  }
});
```

### 2. Configure Tool Provider

```typescript
import { ToolProvider } from '@etdi/sdk';

const provider = new ToolProvider({
  name: 'MyToolProvider',
  version: '1.0.0',
  publicKey: 'your-public-key',
  privateKey: 'your-private-key'
});
```

### 3. Define a Tool

```typescript
import { ToolDefinition } from '@etdi/sdk';

const toolDefinition: ToolDefinition = {
  id: 'my-tool',
  name: 'My Tool',
  version: '1.0.0',
  description: 'A sample tool implementation',
  provider: {
    id: provider.id,
    name: provider.name
  },
  permissions: ['read:data', 'write:data'],
  schema: {
    // JSON Schema for tool input/output
  }
};
```

### 4. Register and Sign Tool

```typescript
// Register tool with provider
const signedTool = await provider.registerTool(toolDefinition);

// Verify tool signature
const isValid = await client.verifyTool(signedTool);
```

### 5. Implement Tool Discovery

```typescript
// Discover available tools
const tools = await client.discoverTools();

// Filter and verify tools
const verifiedTools = tools.filter(tool => tool.verificationStatus === 'VERIFIED');
```

### 6. Handle Tool Invocation

```typescript
// Request tool usage
const result = await client.invokeTool('my-tool', {
  // Tool parameters
});

// Handle tool response
console.log(result);
```

## Security Implementation

### 1. Configure OAuth

```typescript
import { OAuthManager } from '@etdi/oauth';

const oauthManager = new OAuthManager({
  provider: 'auth0',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  domain: 'your-auth0-domain'
});
```

### 2. Implement Permission Checks

```typescript
// Check tool permissions
const hasPermission = await client.checkPermission('my-tool', 'read:data');

if (!hasPermission) {
  throw new Error('Insufficient permissions');
}
```

### 3. Handle Version Changes

```typescript
// Check for version changes
const versionChanged = await client.checkVersionChange('my-tool');

if (versionChanged) {
  // Request re-approval
  await client.requestReapproval('my-tool');
}
```

## Next Steps

1. Review the [OAuth Integration Guide](oauth-integration.md) for detailed OAuth implementation
2. Check the [Best Practices](best-practices.md) for implementation recommendations
3. Explore the [TypeScript SDK Documentation](../development/typescript-sdk.md) for advanced features
4. Review the [Security Model](../core/security.md) for security considerations

## Troubleshooting

### Common Issues

1. **Tool Verification Fails**
   - Check provider keys
   - Verify tool signature
   - Ensure correct version

2. **OAuth Integration Issues**
   - Verify OAuth configuration
   - Check token validity
   - Ensure correct scopes

3. **Permission Errors**
   - Verify permission declarations
   - Check user consent
   - Review scope configuration

## Support

For additional help:
- Check the [API Reference](../development/api-reference.md)
- Review the [Examples](../development/examples.md)
- Join our [Community Forum](https://community.etdi.io)
- Submit an [Issue](https://github.com/etdi/issues) 