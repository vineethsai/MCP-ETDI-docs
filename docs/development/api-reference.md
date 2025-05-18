# ETDI API Reference

This document provides a comprehensive reference for all classes, interfaces, and methods in the ETDI SDK.

## Table of Contents

- [Client API](#client-api)
  - [ETDIClient](#etdiclient)
  - [ToolProvider](#toolprovider)
  - [OAuthManager](#oauthmanager)
- [Data Types](#data-types)
  - [ToolDefinition](#tooldefinition)
  - [SignedToolDefinition](#signedtooldefinition)
  - [Permission](#permission)
  - [ToolApprovalRecord](#toolapprovalrecord)
- [Configuration Types](#configuration-types)
  - [ETDIClientConfig](#etdiclientconfig)
  - [OAuthConfig](#oauthconfig)
  - [KeyConfig](#keyconfig)
  - [StorageConfig](#storageconfig)
- [Error Types](#error-types)
  - [ETDIError](#etdierror)
  - [SignatureError](#signatureerror)
  - [VersionError](#versionerror)
  - [PermissionError](#permissionerror)
- [Events](#events)
- [Constants and Enums](#constants-and-enums)

---

## Client API

### ETDIClient

The primary client for interacting with ETDI-enabled tools.

#### Constructor

```typescript
constructor(config: ETDIClientConfig)
```

Creates a new ETDIClient instance with the specified configuration.

**Parameters:**
- `config: ETDIClientConfig` - Configuration for the client

#### Methods

##### discoverTools

```typescript
async discoverTools(): Promise<ToolDefinition[]>
```

Discovers available tools from connected servers.

**Returns:**
- `Promise<ToolDefinition[]>` - Array of discovered tools

##### verifyTool

```typescript
async verifyTool(tool: ToolDefinition): Promise<boolean>
```

Verifies a tool's signature.

**Parameters:**
- `tool: ToolDefinition` - Tool definition to verify

**Returns:**
- `Promise<boolean>` - True if the tool signature is valid

**Throws:**
- `SignatureError` - If signature verification fails

##### approveTool

```typescript
async approveTool(tool: ToolDefinition): Promise<void>
```

Approves a tool for usage and stores the approval record.

**Parameters:**
- `tool: ToolDefinition` - Tool definition to approve

**Throws:**
- `SignatureError` - If signature verification fails before approval
- `PermissionError` - If permission validation fails

##### isToolApproved

```typescript
async isToolApproved(toolId: string): Promise<boolean>
```

Checks if a tool has been approved.

**Parameters:**
- `toolId: string` - ID of the tool to check

**Returns:**
- `Promise<boolean>` - True if the tool has been approved

##### invokeTool

```typescript
async invokeTool(toolId: string, params: any): Promise<any>
```

Invokes a tool with parameters.

**Parameters:**
- `toolId: string` - ID of the tool to invoke
- `params: any` - Parameters for the tool

**Returns:**
- `Promise<any>` - Result from the tool invocation

**Throws:**
- `ETDIError` - If tool invocation fails

##### checkVersionChange

```typescript
async checkVersionChange(toolId: string): Promise<boolean>
```

Checks if a tool's version has changed since approval.

**Parameters:**
- `toolId: string` - ID of the tool to check

**Returns:**
- `Promise<boolean>` - True if the version has changed

##### requestReapproval

```typescript
async requestReapproval(toolId: string): Promise<void>
```

Requests re-approval for a tool.

**Parameters:**
- `toolId: string` - ID of the tool to request re-approval for

**Throws:**
- `ETDIError` - If re-approval request fails

##### checkPermission

```typescript
async checkPermission(toolId: string, permission: string): Promise<boolean>
```

Checks if a tool has a specific permission.

**Parameters:**
- `toolId: string` - ID of the tool to check
- `permission: string` - Permission to check

**Returns:**
- `Promise<boolean>` - True if the tool has the permission

##### on

```typescript
on(event: string, listener: Function): this
```

Registers an event listener.

**Parameters:**
- `event: string` - Event name
- `listener: Function` - Callback function

**Returns:**
- `this` - The client instance for chaining

##### off

```typescript
off(event: string, listener: Function): this
```

Removes an event listener.

**Parameters:**
- `event: string` - Event name
- `listener: Function` - Callback function to remove

**Returns:**
- `this` - The client instance for chaining

---

### ToolProvider

Used by tool developers to create and register tools.

#### Constructor

```typescript
constructor(config: ToolProviderConfig)
```

Creates a new ToolProvider instance.

**Parameters:**
- `config: ToolProviderConfig` - Configuration for the provider

#### Methods

##### registerTool

```typescript
async registerTool(definition: ToolDefinition): Promise<SignedToolDefinition>
```

Registers a new tool and signs its definition.

**Parameters:**
- `definition: ToolDefinition` - Tool definition to register

**Returns:**
- `Promise<SignedToolDefinition>` - Signed tool definition

**Throws:**
- `ETDIError` - If registration fails

##### updateTool

```typescript
async updateTool(toolId: string, definition: ToolDefinition): Promise<SignedToolDefinition>
```

Updates an existing tool.

**Parameters:**
- `toolId: string` - ID of the tool to update
- `definition: ToolDefinition` - New tool definition

**Returns:**
- `Promise<SignedToolDefinition>` - Updated signed tool definition

**Throws:**
- `ETDIError` - If update fails

##### getTools

```typescript
async getTools(): Promise<SignedToolDefinition[]>
```

Gets a list of all registered tools.

**Returns:**
- `Promise<SignedToolDefinition[]>` - Array of signed tool definitions

##### removeTool

```typescript
async removeTool(toolId: string): Promise<boolean>
```

Removes a tool.

**Parameters:**
- `toolId: string` - ID of the tool to remove

**Returns:**
- `Promise<boolean>` - True if the tool was removed

---

### OAuthManager

Handles OAuth-related operations.

#### Constructor

```typescript
constructor(config: OAuthConfig)
```

Creates a new OAuthManager instance.

**Parameters:**
- `config: OAuthConfig` - OAuth configuration

#### Methods

##### initialize

```typescript
async initialize(): Promise<void>
```

Initializes the manager.

**Throws:**
- `ETDIError` - If initialization fails

##### getToken

```typescript
async getToken(): Promise<string>
```

Gets an OAuth token.

**Returns:**
- `Promise<string>` - JWT token

**Throws:**
- `ETDIError` - If token acquisition fails

##### validateToken

```typescript
async validateToken(token: string): Promise<boolean>
```

Validates an OAuth token.

**Parameters:**
- `token: string` - Token to validate

**Returns:**
- `Promise<boolean>` - True if the token is valid

##### refreshToken

```typescript
async refreshToken(token: string): Promise<string>
```

Refreshes an OAuth token.

**Parameters:**
- `token: string` - Token to refresh

**Returns:**
- `Promise<string>` - New JWT token

**Throws:**
- `ETDIError` - If token refresh fails

##### hasScopes

```typescript
async hasScopes(scopes: string[]): Promise<boolean>
```

Checks if the current token has the specified scopes.

**Parameters:**
- `scopes: string[]` - Scopes to check

**Returns:**
- `Promise<boolean>` - True if the token has all specified scopes

##### requestScopes

```typescript
async requestScopes(scopes: string[]): Promise<string>
```

Requests additional scopes.

**Parameters:**
- `scopes: string[]` - Scopes to request

**Returns:**
- `Promise<string>` - New JWT token with requested scopes

**Throws:**
- `ETDIError` - If scope request fails

---

## Data Types

### ToolDefinition

Represents a tool definition.

```typescript
interface ToolDefinition {
  id: string;
  name: string;
  version: string;
  description: string;
  provider: {
    id: string;
    name: string;
  };
  schema: JSONSchema;
  permissions: Permission[];
}
```

**Properties:**
- `id: string` - Unique identifier for the tool
- `name: string` - Human-readable name
- `version: string` - Semantic version (MAJOR.MINOR.PATCH)
- `description: string` - Human-readable description
- `provider: { id: string; name: string; }` - Provider information
- `schema: JSONSchema` - JSON Schema defining input/output
- `permissions: Permission[]` - Required permissions

### SignedToolDefinition

Represents a signed tool definition.

```typescript
interface SignedToolDefinition extends ToolDefinition {
  signature: string;
  signatureAlgorithm: string;
  oauth?: {
    token: string;
    idp: string;
  };
}
```

**Properties:**
- All properties from `ToolDefinition`
- `signature: string` - Base64-encoded signature of the definition
- `signatureAlgorithm: string` - Signature algorithm used
- `oauth?: { token: string; idp: string; }` - Optional OAuth token information

### Permission

Represents a permission required by a tool.

```typescript
interface Permission {
  name: string;
  description: string;
  scope: string;
  required: boolean;
}
```

**Properties:**
- `name: string` - Permission name
- `description: string` - Human-readable description
- `scope: string` - OAuth scope equivalent
- `required: boolean` - Whether the permission is required

### ToolApprovalRecord

Represents a stored approval record.

```typescript
interface ToolApprovalRecord {
  toolId: string;
  providerPublicKeyId: string;
  approvedVersion: string;
  definitionHash: string;
  approvalDate: Date;
  permissions: Permission[];
  expiryDate?: Date;
}
```

**Properties:**
- `toolId: string` - Tool identifier
- `providerPublicKeyId: string` - Identifier for the provider's public key used
- `approvedVersion: string` - Version that was approved
- `definitionHash: string` - Hash of the complete definition
- `approvalDate: Date` - When the approval was granted
- `permissions: Permission[]` - Permissions that were approved
- `expiryDate?: Date` - Optional expiration of approval

---

## Configuration Types

### ETDIClientConfig

Configuration for ETDIClient.

```typescript
interface ETDIClientConfig {
  securityLevel: 'basic' | 'enhanced' | 'strict';
  oauthConfig?: OAuthConfig;
  keyConfig?: KeyConfig;
  storageConfig?: StorageConfig;
  options?: ClientOptions;
}
```

**Properties:**
- `securityLevel: 'basic' | 'enhanced' | 'strict'` - Security level to use
- `oauthConfig?: OAuthConfig` - OAuth configuration (required for enhanced and strict)
- `keyConfig?: KeyConfig` - Key configuration (required for basic)
- `storageConfig?: StorageConfig` - Storage configuration
- `options?: ClientOptions` - Additional options

### OAuthConfig

Configuration for OAuth.

```typescript
interface OAuthConfig {
  provider: string | CustomOAuthProvider;
  clientId?: string;
  clientSecret?: string;
  domain?: string;
  audience?: string;
  scopes?: string[];
  tenantId?: string;
}
```

**Properties:**
- `provider: string | CustomOAuthProvider` - OAuth provider ('auth0', 'okta', 'azure', 'custom') or custom provider instance
- `clientId?: string` - Client ID
- `clientSecret?: string` - Client secret
- `domain?: string` - Provider domain
- `audience?: string` - API audience
- `scopes?: string[]` - Default scopes
- `tenantId?: string` - Tenant ID (for Azure AD)

### KeyConfig

Configuration for cryptographic keys.

```typescript
interface KeyConfig {
  keyStorage: string | CustomKeyStorage;
  trustedProviders?: TrustedProvider[];
}
```

**Properties:**
- `keyStorage: string | CustomKeyStorage` - Key storage type or custom storage instance
- `trustedProviders?: TrustedProvider[]` - List of trusted providers

### StorageConfig

Configuration for storage.

```typescript
interface StorageConfig {
  provider: string | CustomStorageProvider;
  options?: StorageOptions;
}
```

**Properties:**
- `provider: string | CustomStorageProvider` - Storage provider type or custom provider instance
- `options?: StorageOptions` - Storage options

---

## Error Types

### ETDIError

Base error class for ETDI.

```typescript
class ETDIError extends Error {
  code: string;
  cause?: Error;
}
```

**Properties:**
- `code: string` - Error code
- `cause?: Error` - Optional original error

### SignatureError

Error for signature verification failures.

```typescript
class SignatureError extends ETDIError {
  // Inherits properties from ETDIError
}
```

### VersionError

Error for version mismatch issues.

```typescript
class VersionError extends ETDIError {
  oldVersion: string;
  newVersion: string;
}
```

**Properties:**
- All properties from `ETDIError`
- `oldVersion: string` - Previously approved version
- `newVersion: string` - New version

### PermissionError

Error for permission validation failures.

```typescript
class PermissionError extends ETDIError {
  requiredPermissions: Permission[];
  approvedPermissions: Permission[];
}
```

**Properties:**
- All properties from `ETDIError`
- `requiredPermissions: Permission[]` - Required permissions
- `approvedPermissions: Permission[]` - Approved permissions

---

## Events

Events emitted by ETDIClient.

| Event Name | Payload | Description |
|------------|---------|-------------|
| `toolVerified` | `ToolDefinition` | Emitted when a tool is verified |
| `toolApproved` | `ToolDefinition` | Emitted when a tool is approved |
| `versionChanged` | `{ tool: ToolDefinition, oldVersion: string, newVersion: string }` | Emitted when a tool version changes |
| `permissionChanged` | `{ tool: ToolDefinition, changes: PermissionChange[] }` | Emitted when tool permissions change |
| `tokenRefreshed` | `{ token: string }` | Emitted when an OAuth token is refreshed |
| `tokenExpired` | `{ token: string }` | Emitted when an OAuth token expires |
| `error` | `ETDIError` | Emitted on errors |

---

## Constants and Enums

### SecurityLevel

```typescript
enum SecurityLevel {
  BASIC = 'basic',
  ENHANCED = 'enhanced',
  STRICT = 'strict'
}
```

### VerificationStatus

```typescript
enum VerificationStatus {
  VERIFIED = 'VERIFIED',
  UNVERIFIED = 'UNVERIFIED',
  SIGNATURE_INVALID = 'SIGNATURE_INVALID',
  PROVIDER_UNKNOWN = 'PROVIDER_UNKNOWN'
}
```

### ErrorCode

```typescript
enum ErrorCode {
  SIGNATURE_INVALID = 'SIGNATURE_INVALID',
  PROVIDER_NOT_FOUND = 'PROVIDER_NOT_FOUND',
  VERSION_MISMATCH = 'VERSION_MISMATCH',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  SCOPE_MISSING = 'SCOPE_MISSING',
  NETWORK_ERROR = 'NETWORK_ERROR',
  STORAGE_ERROR = 'STORAGE_ERROR',
  INTERNAL_ERROR = 'INTERNAL_ERROR'
}
``` 