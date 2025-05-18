# TypeScript SDK Documentation

This document provides detailed information about the ETDI TypeScript SDK.

## Installation

```bash
npm install @etdi/sdk
# or
yarn add @etdi/sdk
```

## Core Components

### ETDIClient

The `ETDIClient` is the main entry point for applications using ETDI.

```typescript
import { ETDIClient } from '@etdi/sdk';

const client = new ETDIClient({
  securityLevel: 'enhanced',
  oauthConfig: {
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain'
  }
});
```

#### Configuration Options

```typescript
interface ETDIClientConfig {
  // Security level to use (basic, enhanced, or strict)
  securityLevel: 'basic' | 'enhanced' | 'strict';
  
  // OAuth configuration (required for enhanced and strict)
  oauthConfig?: OAuthConfig;
  
  // Cryptographic key configuration (required for basic)
  keyConfig?: KeyConfig;
  
  // Storage configuration for approvals and signatures
  storageConfig?: StorageConfig;
  
  // Options for timeout, retry, and caching
  options?: ClientOptions;
}
```

#### Methods

```typescript
class ETDIClient {
  // Discover available tools from connected servers
  async discoverTools(): Promise<ToolDefinition[]>;
  
  // Verify a tool's signature
  async verifyTool(tool: ToolDefinition): Promise<boolean>;
  
  // Approve a tool for usage
  async approveTool(tool: ToolDefinition): Promise<void>;
  
  // Check if a tool has been approved
  async isToolApproved(toolId: string): Promise<boolean>;
  
  // Invoke a tool with parameters
  async invokeTool(toolId: string, params: any): Promise<any>;
  
  // Check for tool version changes
  async checkVersionChange(toolId: string): Promise<boolean>;
  
  // Request re-approval for a tool
  async requestReapproval(toolId: string): Promise<void>;
}
```

### ToolProvider

The `ToolProvider` is used by tool developers to create and register tools.

```typescript
import { ToolProvider } from '@etdi/sdk';

const provider = new ToolProvider({
  name: 'MyToolProvider',
  version: '1.0.0',
  publicKey: 'your-public-key',
  privateKey: 'your-private-key'
});
```

#### Methods

```typescript
class ToolProvider {
  // Register a new tool
  async registerTool(definition: ToolDefinition): Promise<SignedToolDefinition>;
  
  // Update an existing tool
  async updateTool(toolId: string, definition: ToolDefinition): Promise<SignedToolDefinition>;
  
  // Get a list of registered tools
  async getTools(): Promise<SignedToolDefinition[]>;
  
  // Remove a tool
  async removeTool(toolId: string): Promise<boolean>;
}
```

### OAuthManager

The `OAuthManager` handles OAuth-related operations.

```typescript
import { OAuthManager } from '@etdi/sdk';

const manager = new OAuthManager({
  provider: 'auth0',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  domain: 'your-auth0-domain'
});
```

#### Methods

```typescript
class OAuthManager {
  // Initialize the manager
  async initialize(): Promise<void>;
  
  // Get a token
  async getToken(): Promise<string>;
  
  // Validate a token
  async validateToken(token: string): Promise<boolean>;
  
  // Refresh a token
  async refreshToken(token: string): Promise<string>;
  
  // Check if the token has specified scopes
  async hasScopes(scopes: string[]): Promise<boolean>;
  
  // Request additional scopes
  async requestScopes(scopes: string[]): Promise<string>;
}
```

## Data Types

### ToolDefinition

```typescript
interface ToolDefinition {
  // Unique identifier for the tool
  id: string;
  
  // Human-readable name
  name: string;
  
  // Semantic version (MAJOR.MINOR.PATCH)
  version: string;
  
  // Human-readable description
  description: string;
  
  // Provider information
  provider: {
    id: string;
    name: string;
  };
  
  // JSON Schema defining input/output
  schema: JSONSchema;
  
  // Required permissions
  permissions: Permission[];
}
```

### SignedToolDefinition

```typescript
interface SignedToolDefinition extends ToolDefinition {
  // Base64-encoded signature of the definition
  signature: string;
  
  // Signature algorithm used
  signatureAlgorithm: string;
  
  // Optional OAuth token
  oauth?: {
    token: string;
    idp: string;
  };
}
```

### Permission

```typescript
interface Permission {
  // Permission name
  name: string;
  
  // Human-readable description
  description: string;
  
  // OAuth scope equivalent
  scope: string;
  
  // Whether the permission is required
  required: boolean;
}
```

## Usage Examples

### Basic Tool Discovery and Invocation

```typescript
import { ETDIClient } from '@etdi/sdk';

async function main() {
  // Initialize client
  const client = new ETDIClient({
    securityLevel: 'enhanced',
    oauthConfig: {
      provider: 'auth0',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      domain: 'your-auth0-domain'
    }
  });
  
  // Discover tools
  const tools = await client.discoverTools();
  
  // Filter verified tools
  const verifiedTools = tools.filter(tool => 
    tool.verificationStatus === 'VERIFIED'
  );
  
  // Display available tools
  console.log('Available tools:');
  verifiedTools.forEach(tool => {
    console.log(`- ${tool.name} (${tool.version})`);
  });
  
  // Invoke a tool
  if (verifiedTools.length > 0) {
    const tool = verifiedTools[0];
    console.log(`Invoking ${tool.name}...`);
    
    const result = await client.invokeTool(tool.id, {
      // Tool parameters
    });
    
    console.log('Result:', result);
  }
}

main().catch(console.error);
```

### Creating and Registering a Tool

```typescript
import { ToolProvider, ToolDefinition } from '@etdi/sdk';

async function registerTool() {
  // Initialize provider
  const provider = new ToolProvider({
    name: 'MyToolProvider',
    version: '1.0.0',
    publicKey: 'your-public-key',
    privateKey: 'your-private-key'
  });
  
  // Define tool
  const toolDefinition: ToolDefinition = {
    id: 'my-tool',
    name: 'My Tool',
    version: '1.0.0',
    description: 'A sample tool implementation',
    provider: {
      id: provider.id,
      name: provider.name
    },
    permissions: [
      {
        name: 'read:data',
        description: 'Read data from the system',
        scope: 'read:data',
        required: true
      },
      {
        name: 'write:data',
        description: 'Write data to the system',
        scope: 'write:data',
        required: false
      }
    ],
    schema: {
      // JSON Schema for tool input/output
    }
  };
  
  // Register tool
  const signedTool = await provider.registerTool(toolDefinition);
  
  console.log('Tool registered successfully:', signedTool);
}

registerTool().catch(console.error);
```

### Advanced OAuth Integration

```typescript
import { ETDIClient, OAuthManager } from '@etdi/sdk';

async function setupWithOAuth() {
  // Initialize OAuth manager
  const oauthManager = new OAuthManager({
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain',
    audience: 'your-audience',
    scopes: ['openid', 'profile', 'email']
  });
  
  // Initialize manager
  await oauthManager.initialize();
  
  // Get token
  const token = await oauthManager.getToken();
  
  // Initialize ETDI client with OAuth manager
  const client = new ETDIClient({
    securityLevel: 'enhanced',
    oauthManager
  });
  
  // Use client
  const tools = await client.discoverTools();
  
  // Check permissions
  const hasPermissions = await client.checkPermission('my-tool', 'read:data');
  
  if (hasPermissions) {
    // Invoke tool
    const result = await client.invokeTool('my-tool', {
      // Tool parameters
    });
    
    console.log('Result:', result);
  }
}

setupWithOAuth().catch(console.error);
```

## Error Handling

```typescript
import { ETDIClient, ETDIError } from '@etdi/sdk';

async function handleErrors() {
  const client = new ETDIClient({
    securityLevel: 'enhanced',
    oauthConfig: {
      provider: 'auth0',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      domain: 'your-auth0-domain'
    }
  });
  
  try {
    await client.verifyTool(tool);
  } catch (error) {
    if (error instanceof ETDIError) {
      switch (error.code) {
        case 'SIGNATURE_INVALID':
          console.error('Tool signature is invalid');
          break;
        case 'PROVIDER_NOT_FOUND':
          console.error('Provider not found');
          break;
        case 'VERSION_MISMATCH':
          console.error('Version mismatch detected');
          break;
        default:
          console.error('Unknown ETDI error:', error.message);
      }
    } else {
      console.error('Unexpected error:', error);
    }
  }
}

handleErrors().catch(console.error);
```

## Events

```typescript
import { ETDIClient } from '@etdi/sdk';

function setupEvents() {
  const client = new ETDIClient({
    securityLevel: 'enhanced',
    oauthConfig: {
      provider: 'auth0',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      domain: 'your-auth0-domain'
    }
  });
  
  // Tool events
  client.on('toolVerified', (tool) => {
    console.log(`Tool ${tool.name} verified successfully`);
  });
  
  client.on('toolApproved', (tool) => {
    console.log(`Tool ${tool.name} approved by user`);
  });
  
  client.on('versionChanged', (tool) => {
    console.log(`Tool ${tool.name} version changed from ${tool.oldVersion} to ${tool.newVersion}`);
  });
  
  client.on('permissionChanged', (tool) => {
    console.log(`Tool ${tool.name} permissions changed`);
  });
  
  // OAuth events
  client.on('tokenRefreshed', () => {
    console.log('OAuth token refreshed');
  });
  
  client.on('tokenExpired', () => {
    console.log('OAuth token expired');
  });
}

setupEvents();
```

## Advanced Configuration

### Custom Provider

```typescript
import { CustomOAuthProvider, OAuthManager } from '@etdi/sdk';

async function setupCustomProvider() {
  // Implement custom provider
  class MyCustomProvider extends CustomOAuthProvider {
    async getToken() {
      // Custom token acquisition logic
    }
    
    async validateToken(token) {
      // Custom token validation logic
    }
    
    async refreshToken(token) {
      // Custom token refresh logic
    }
  }
  
  // Register custom provider
  const provider = new MyCustomProvider({
    // Provider-specific configuration
  });
  
  // Use custom provider
  const oauthManager = new OAuthManager({
    provider: provider
  });
  
  // Continue with normal flow
}

setupCustomProvider().catch(console.error);
```

### Custom Storage

```typescript
import { CustomStorageProvider, ETDIClient } from '@etdi/sdk';

async function setupCustomStorage() {
  // Implement custom storage
  class MyStorageProvider extends CustomStorageProvider {
    async storeApproval(record) {
      // Custom storage logic
    }
    
    async getApproval(toolId) {
      // Custom retrieval logic
    }
    
    async removeApproval(toolId) {
      // Custom removal logic
    }
  }
  
  // Use custom storage
  const storage = new MyStorageProvider();
  
  const client = new ETDIClient({
    securityLevel: 'enhanced',
    storageConfig: {
      provider: storage
    },
    oauthConfig: {
      provider: 'auth0',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      domain: 'your-auth0-domain'
    }
  });
  
  // Continue with normal flow
}

setupCustomStorage().catch(console.error);
```

## Next Steps

- Check the [API Reference](api-reference.md) for a complete list of classes, methods, and interfaces
- Look at the [Examples](examples.md) for more detailed code samples
- Review the [Best Practices](../implementation/best-practices.md) for implementation recommendations 