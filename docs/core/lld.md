# Enhanced Tool Definition Interface (ETDI) - Low-Level Design Document

## 1. Introduction

This Low-Level Design (LLD) document specifies the technical implementation details for the Enhanced Tool Definition Interface (ETDI), a security extension to the Model Context Protocol (MCP). ETDI addresses critical security vulnerabilities in MCP, specifically Tool Poisoning and Rug Pull attacks, by implementing cryptographic verification, immutable versioned definitions, and explicit permission management.

### 1.1 Document Purpose

This document provides developers with specific implementation guidance for modifying MCP Clients, MCP Servers, and integrating OAuth 2.0 authorization to create a secure MCP ecosystem. It serves as a technical blueprint for ETDI adoption.

### 1.2 Scope

This design covers:
- Detailed modifications to MCP Client components
- Required changes to MCP Server implementations
- OAuth 2.0 integration specifics
- Key management infrastructure
- Security implementation details
- Backward compatibility considerations

## 2. System Component Modifications

### 2.1 Modified Component Architecture

```mermaid
flowchart TD
    User([User])
    Host[Host Application]
    Client[MCP Client]
    Server[MCP Server]
    Tool[Tool Implementation]
    IdP[OAuth Identity Provider]
    
    subgraph "MCP Client Modifications"
        ClientMod1[Tool Verification Module]
        ClientMod2[Signature Storage]
        ClientMod3[Version Tracking]
        ClientMod4[OAuth Client Module]
    end
    
    subgraph "MCP Server Modifications"
        ServerMod1[Tool Definition Signing]
        ServerMod2[OAuth Integration]
        ServerMod3[Version Management]
    end
    
    subgraph "OAuth Components"
        IdPReg[Provider Registration]
        IdPToken[Token Issuance]
        IdPValid[Token Validation]
    end
    
    Client --> ClientMod1
    Client --> ClientMod2
    Client --> ClientMod3
    Client --> ClientMod4
    
    Server --> ServerMod1
    Server --> ServerMod2
    Server --> ServerMod3
    
    IdP --> IdPReg
    IdP --> IdPToken
    IdP --> IdPValid
    
    ClientMod4 <--> IdPValid
    ServerMod2 <--> IdPToken
    Tool <--> ServerMod1
    
    User <--> Host
    Host <--> Client
    Client <--> Server
    Server <--> Tool
```

## 3. MCP Client Implementation Details

### 3.1 Core Data Structures

```typescript
// Tool definition with security extensions
interface ETDIToolDefinition {
    id: string;                 // Unique identifier for the tool
    name: string;               // Human-readable name
    version: string;            // Semantic version (MAJOR.MINOR.PATCH)
    description: string;        // Human-readable description
    provider: {
        id: string;             // Unique identifier for the provider
        name: string;           // Human-readable provider name
    };
    schema: JSONSchema;         // JSON Schema defining input/output
    permissions: Permission[];  // Required permissions
    signature: string;          // Base64-encoded signature of the definition
    signatureAlgorithm: string; // e.g., "ES256", "RS256"
    oauth?: {
        token: string;          // JWT token (for OAuth-enhanced ETDI)
        idp: string;            // Identity Provider identifier
    };
}

// Stored approval record
interface ToolApprovalRecord {
    toolId: string;            // Tool identifier
    providerPublicKeyId: string;// Identifier for the provider's public key used
    approvedVersion: string;    // Version that was approved
    definitionHash: string;     // Hash of the complete definition
    approvalDate: Date;         // When the approval was granted
    permissions: Permission[];  // Permissions that were approved
    expiryDate?: Date;          // Optional expiration of approval
}
```

### 3.2 Tool Discovery Enhancement

```typescript
class ETDIClient extends MCPClient {
    // Override the standard tool discovery method
    async discoverTools(): Promise<ETDIToolDefinition[]> {
        // Get tools from all connected servers using standard MCP
        const tools = await super.discoverTools();
        
        // Filter and verify each tool
        const verifiedTools = [];
        for (const tool of tools) {
            // Skip tools without ETDI signatures
            if (!this.hasETDISignature(tool)) {
                if (this.config.allowNonETDITools) {
                    tool.verificationStatus = 'UNVERIFIED';
                    verifiedTools.push(tool);
                }
                continue;
            }
            
            // Verify tool signature
            const isVerified = await this.verifyToolSignature(tool);
            if (isVerified) {
                tool.verificationStatus = 'VERIFIED';
                verifiedTools.push(tool);
            } else if (this.config.showUnverifiedTools) {
                tool.verificationStatus = 'SIGNATURE_INVALID';
                verifiedTools.push(tool);
            }
        }
        
        return verifiedTools;
    }
}
```

### 3.3 Signature Verification

```typescript
class ETDIClient extends MCPClient {
    async verifyToolSignature(tool: ETDIToolDefinition): Promise<boolean> {
        // For OAuth-enhanced ETDI
        if (tool.oauth && tool.oauth.token) {
            return this.verifyOAuthToken(tool.oauth.token, tool.oauth.idp);
        }
        
        // For direct signature verification
        try {
            // Get provider's public key
            const providerPublicKey = await this.keyStore.getPublicKey(
                tool.provider.id
            );
            
            if (!providerPublicKey) {
                console.warn(`No public key found for provider: ${tool.provider.id}`);
                return false;
            }
            
            // Create verification data (everything except the signature)
            const dataToVerify = this.createSignaturePayload(tool);
            
            // Verify signature
            return this.cryptoService.verify(
                dataToVerify,
                tool.signature,
                providerPublicKey,
                tool.signatureAlgorithm
            );
        } catch (error) {
            console.error(`Signature verification error: ${error.message}`);
            return false;
        }
    }
    
    createSignaturePayload(tool: ETDIToolDefinition): string {
        // Create a copy of the tool without the signature
        const { signature, ...toolWithoutSignature } = tool;
        
        // Sort keys to ensure consistent order
        return JSON.stringify(toolWithoutSignature, Object.keys(toolWithoutSignature).sort());
    }
}
```

### 3.4 Tool Approval and Storage

```typescript
class ETDIClient extends MCPClient {
    async approveToolWithETDI(tool: ETDIToolDefinition, 
                             approvedPermissions: Permission[]): Promise<boolean> {
        // Verify the tool one more time before approval
        const isVerified = await this.verifyToolSignature(tool);
        if (!isVerified) {
            throw new Error('Cannot approve a tool with invalid signature');
        }
        
        // Create a hash of the tool definition for future integrity checks
        const definitionHash = await this.cryptoService.hash(
            this.createSignaturePayload(tool)
        );
        
        // Create approval record
        const approvalRecord: ToolApprovalRecord = {
            toolId: tool.id,
            providerPublicKeyId: tool.provider.id,
            approvedVersion: tool.version,
            definitionHash,
            approvalDate: new Date(),
            permissions: approvedPermissions,
        };
        
        // Store the approval record
        await this.approvalStore.storeApproval(approvalRecord);
        
        return true;
    }
}
```

### 3.5 Re-verification on Subsequent Use

```typescript
class ETDIClient extends MCPClient {
    async checkToolBeforeInvocation(tool: ETDIToolDefinition): Promise<{
        canProceed: boolean;
        requiresReapproval: boolean;
        reason?: string;
    }> {
        // First, verify the signature is valid
        const isSignatureValid = await this.verifyToolSignature(tool);
        if (!isSignatureValid) {
            return {
                canProceed: false,
                requiresReapproval: false,
                reason: 'INVALID_SIGNATURE',
            };
        }
        
        // Get the stored approval record
        const approvalRecord = await this.approvalStore.getApproval(tool.id);
        if (!approvalRecord) {
            return {
                canProceed: false,
                requiresReapproval: true,
                reason: 'NOT_APPROVED',
            };
        }
        
        // Check for version changes
        if (tool.version !== approvalRecord.approvedVersion) {
            return {
                canProceed: false,
                requiresReapproval: true,
                reason: 'VERSION_CHANGED',
            };
        }
        
        // Check for definition changes (rug pull attempt detection)
        const currentDefinitionHash = await this.cryptoService.hash(
            this.createSignaturePayload(tool)
        );
        
        if (currentDefinitionHash !== approvalRecord.definitionHash) {
            return {
                canProceed: false,
                requiresReapproval: true,
                reason: 'DEFINITION_CHANGED',
            };
        }
        
        // Check for permission changes
        const hasNewPermissions = this.checkForNewPermissions(
            tool.permissions,
            approvalRecord.permissions
        );
        
        if (hasNewPermissions) {
            return {
                canProceed: false,
                requiresReapproval: true,
                reason: 'PERMISSIONS_CHANGED',
            };
        }
        
        // All checks passed
        return {
            canProceed: true,
            requiresReapproval: false,
        };
    }
}
```

### 3.6 OAuth Client Module Implementation

```typescript
class OAuthClientModule {
    private tokenCache: Map<string, {
        token: string;
        expiry: Date;
    }> = new Map();
    
    constructor(
        private config: {
            clientId: string;
            clientSecret: string;
            redirectUri: string;
            idpMap: Record<string, string>; // Maps IdP IDs to their endpoints
        }
    ) {}
    
    async verifyOAuthToken(token: string, idpId: string): Promise<boolean> {
        try {
            // Get the IdP endpoint
            const idpEndpoint = this.config.idpMap[idpId];
            if (!idpEndpoint) {
                console.error(`Unknown IdP: ${idpId}`);
                return false;
            }
            
            // Option 1: Local verification using IdP's public key (faster)
            const idpPublicKey = await this.getIdpPublicKey(idpId);
            if (idpPublicKey) {
                return this.verifyJwtLocally(token, idpPublicKey);
            }
            
            // Option 2: Send to IdP for verification (more current)
            const response = await fetch(`${idpEndpoint}/introspect`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
                },
                body: `token=${encodeURIComponent(token)}`,
            });
            
            if (!response.ok) {
                return false;
            }
            
            const introspection = await response.json();
            return introspection.active === true;
        } catch (error) {
            console.error(`OAuth token verification error: ${error.message}`);
            return false;
        }
    }
    
    private async verifyJwtLocally(token: string, publicKey: string): Promise<boolean> {
        // Decode the JWT without verification first
        const [headerB64, payloadB64, signature] = token.split('.');
        
        // Decode the payload
        const payloadJson = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
        const payload = JSON.parse(payloadJson);
        
        // Check token expiry
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            return false;
        }
        
        // Verify the signature
        return this.cryptoService.verifyJwt(token, publicKey);
    }
}
```

## 4. MCP Server Implementation Details

### 4.1 Tool Registration with ETDI Support

```typescript
class ETDIToolRegistry {
    private tools: Map<string, ETDIToolDefinition> = new Map();
    
    constructor(
        private cryptoService: CryptoService,
        private config: {
            providerPrivateKey: string;
            providerId: string;
            providerName: string;
            signatureAlgorithm: string;
        }
    ) {}
    
    async registerTool(toolDefinition: Omit<ETDIToolDefinition, 'signature' | 'provider' | 'signatureAlgorithm'>): Promise<ETDIToolDefinition> {
        // Inject provider information
        const fullDefinition: Omit<ETDIToolDefinition, 'signature'> = {
            ...toolDefinition,
            provider: {
                id: this.config.providerId,
                name: this.config.providerName,
            },
            signatureAlgorithm: this.config.signatureAlgorithm,
        };
        
        // Create signature payload
        const payload = this.createSignaturePayload(fullDefinition);
        
        // Sign the definition
        const signature = await this.cryptoService.sign(
            payload,
            this.config.providerPrivateKey,
            this.config.signatureAlgorithm
        );
        
        // Create complete tool definition with signature
        const completeDefinition: ETDIToolDefinition = {
            ...fullDefinition,
            signature,
        };
        
        // Store in registry
        this.tools.set(completeDefinition.id, completeDefinition);
        
        return completeDefinition;
    }
    
    private createSignaturePayload(tool: Omit<ETDIToolDefinition, 'signature'>): string {
        // Sort keys to ensure consistent order
        return JSON.stringify(tool, Object.keys(tool).sort());
    }
}
```

### 4.2 OAuth Integration for Tool Providers

```typescript
class OAuthToolProvider {
    constructor(
        private toolRegistry: ETDIToolRegistry,
        private cryptoService: CryptoService,
        private config: {
            clientId: string;
            clientSecret: string;
            idpEndpoint: string;
            scopes: string[];
        }
    ) {}
    
    async registerToolWithOAuth(toolDefinition: Omit<ETDIToolDefinition, 'signature' | 'provider' | 'signatureAlgorithm' | 'oauth'>): Promise<ETDIToolDefinition> {
        // First register the tool with standard ETDI to get a signed definition
        const signedDefinition = await this.toolRegistry.registerTool(toolDefinition);
        
        // Now obtain an OAuth token for this tool
        const token = await this.getOAuthToken(signedDefinition);
        
        // Enhance the definition with OAuth information
        const oauthEnhancedDefinition: ETDIToolDefinition = {
            ...signedDefinition,
            oauth: {
                token,
                idp: new URL(this.config.idpEndpoint).hostname,
            },
        };
        
        return oauthEnhancedDefinition;
    }
    
    private async getOAuthToken(toolDefinition: ETDIToolDefinition): Promise<string> {
        // Calculate appropriate scopes based on tool permissions
        const calculatedScopes = this.mapPermissionsToScopes(toolDefinition.permissions);
        
        // Include version in custom claims
        const customClaims = {
            tool_id: toolDefinition.id,
            tool_version: toolDefinition.version,
            tool_provider: toolDefinition.provider.id,
        };
        
        // Request token from IdP
        const tokenRequest = new URLSearchParams();
        tokenRequest.append('grant_type', 'client_credentials');
        tokenRequest.append('scope', calculatedScopes.join(' '));
        tokenRequest.append('tool_claims', JSON.stringify(customClaims));
        
        const response = await fetch(`${this.config.idpEndpoint}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
            },
            body: tokenRequest.toString(),
        });
        
        if (!response.ok) {
            throw new Error(`Failed to obtain OAuth token: ${response.statusText}`);
        }
        
        const tokenResponse = await response.json();
        return tokenResponse.access_token;
    }
    
    private mapPermissionsToScopes(permissions: Permission[]): string[] {
        // Map ETDI permissions to OAuth scopes
        // e.g., 'filesystem:read:/documents' -> 'tool:fs:read:/documents'
        return permissions.map(permission => {
            const [category, action, path] = permission.split(':');
            return `tool:${category}:${action}${path ? `:${path}` : ''}`;
        });
    }
}
```

### 4.3 Version Management Implementation

```typescript
class ToolVersionManager {
    private versionHistory: Map<string, string[]> = new Map();
    
    constructor(private toolRegistry: ETDIToolRegistry) {}
    
    async createNewVersion(
        toolId: string,
        updateFn: (currentDefinition: ETDIToolDefinition) => Partial<ETDIToolDefinition>
    ): Promise<ETDIToolDefinition> {
        // Get current definition
        const currentTool = this.toolRegistry.getTool(toolId);
        if (!currentTool) {
            throw new Error(`Tool not found: ${toolId}`);
        }
        
        // Parse current version
        const [major, minor, patch] = currentTool.version.split('.').map(Number);
        
        // Calculate what kind of update this is
        const updates = updateFn(currentTool);
        
        // Determine version increment type
        let newVersion: string;
        
        if (this.hasPermissionChanges(currentTool.permissions, updates.permissions)) {
            // Permission changes require a major version bump
            newVersion = `${major + 1}.0.0`;
        } else if (this.hasSchemaChanges(currentTool.schema, updates.schema)) {
            // Schema changes require at least a minor version bump
            newVersion = `${major}.${minor + 1}.0`;
        } else {
            // Other changes get a patch bump
            newVersion = `${major}.${minor}.${patch + 1}`;
        }
        
        // Create new definition
        const newDefinition = {
            ...currentTool,
            ...updates,
            version: newVersion,
        };
        
        // Register as new tool (will create signature)
        const registeredTool = await this.toolRegistry.registerTool(newDefinition);
        
        // Store in version history
        if (!this.versionHistory.has(toolId)) {
            this.versionHistory.set(toolId, []);
        }
        this.versionHistory.get(toolId).push(newVersion);
        
        return registeredTool;
    }
    
    private hasPermissionChanges(
        currentPermissions: Permission[] = [],
        newPermissions: Permission[] = []
    ): boolean {
        if (!newPermissions) return false;
        if (currentPermissions.length !== newPermissions.length) return true;
        
        // Check if any new permissions are not in current permissions
        return newPermissions.some(p => !currentPermissions.includes(p));
    }
    
    private hasSchemaChanges(currentSchema: JSONSchema, newSchema: JSONSchema): boolean {
        if (!newSchema) return false;
        
        // Simple deep equality check (in real implementation, a more sophisticated
        // comparison would be needed to detect breaking changes)
        return JSON.stringify(currentSchema) !== JSON.stringify(newSchema);
    }
}
```

## 5. OAuth Identity Provider Implementation

### 5.1 Provider Registration Component

```typescript
class ProviderRegistrationService {
    constructor(
        private db: Database,
        private cryptoService: CryptoService,
        private config: {
            approvalRequired: boolean;
        }
    ) {}
    
    async registerProvider(registrationRequest: {
        name: string;
        description: string;
        contactEmail: string;
        website: string;
        publicKey: string;
        callbackUrl: string;
    }): Promise<{
        providerId: string;
        clientId: string;
        clientSecret: string;
        registrationStatus: 'PENDING' | 'APPROVED';
    }> {
        // Validate the provider's public key
        const isValidKey = this.cryptoService.validatePublicKey(registrationRequest.publicKey);
        if (!isValidKey) {
            throw new Error('Invalid public key format');
        }
        
        // Generate provider ID
        const providerId = await this.cryptoService.generateId();
        
        // Generate OAuth client credentials
        const clientId = await this.cryptoService.generateId();
        const clientSecret = await this.cryptoService.generateRandomString(32);
        
        // Store provider information
        await this.db.storeProvider({
            id: providerId,
            name: registrationRequest.name,
            description: registrationRequest.description,
            contactEmail: registrationRequest.contactEmail,
            website: registrationRequest.website,
            publicKey: registrationRequest.publicKey,
            callbackUrl: registrationRequest.callbackUrl,
            clientId,
            clientSecret: await this.cryptoService.hash(clientSecret), // Store hashed secret
            registrationDate: new Date(),
            status: this.config.approvalRequired ? 'PENDING' : 'APPROVED',
        });
        
        return {
            providerId,
            clientId,
            clientSecret, // Return plain text secret only once
            registrationStatus: this.config.approvalRequired ? 'PENDING' : 'APPROVED',
        };
    }
}
```

### 5.2 Token Issuance Service

```typescript
class TokenIssuanceService {
    constructor(
        private db: Database,
        private cryptoService: CryptoService,
        private config: {
            jwtSigningKey: string;
            jwtAlgorithm: string;
            tokenLifetime: number; // seconds
        }
    ) {}
    
    async issueToken(request: {
        clientId: string;
        clientSecret: string;
        scope: string;
        toolClaims?: {
            tool_id: string;
            tool_version: string;
            tool_provider: string;
        };
    }): Promise<{
        access_token: string;
        token_type: string;
        expires_in: number;
        scope: string;
    }> {
        // Validate client credentials
        const provider = await this.db.getProviderByClientId(request.clientId);
        if (!provider) {
            throw new Error('Invalid client credentials');
        }
        
        const isValidSecret = await this.cryptoService.compare(
            request.clientSecret,
            provider.clientSecret
        );
        
        if (!isValidSecret) {
            throw new Error('Invalid client credentials');
        }
        
        // Check provider status
        if (provider.status !== 'APPROVED') {
            throw new Error('Provider not approved');
        }
        
        // Validate scopes based on provider permissions
        const validatedScopes = this.validateScopes(request.scope, provider.allowedScopes);
        
        // Create JWT payload
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: 'etdi-oauth-idp',  // Issuer
            sub: provider.id,        // Subject (provider ID)
            aud: request.clientId,   // Audience (client ID)
            iat: now,                // Issued at
            exp: now + this.config.tokenLifetime, // Expiration
            jti: await this.cryptoService.generateId(), // JWT ID
            scope: validatedScopes,
            ...request.toolClaims,   // Tool-specific claims if provided
        };
        
        // Sign the JWT
        const token = await this.cryptoService.signJwt(
            payload,
            this.config.jwtSigningKey,
            this.config.jwtAlgorithm
        );
        
        // Log token issuance for auditing
        await this.db.logTokenIssuance({
            jti: payload.jti,
            clientId: request.clientId,
            providerId: provider.id,
            scope: validatedScopes,
            issuedAt: new Date(now * 1000),
            expiresAt: new Date((now + this.config.tokenLifetime) * 1000),
            toolId: request.toolClaims?.tool_id,
        });
        
        return {
            access_token: token,
            token_type: 'Bearer',
            expires_in: this.config.tokenLifetime,
            scope: validatedScopes,
        };
    }
    
    private validateScopes(requestedScopes: string, allowedScopes: string): string {
        const requested = requestedScopes.split(' ');
        const allowed = allowedScopes.split(' ');
        
        // Filter out any scopes that aren't in the allowed list
        const validated = requested.filter(scope => allowed.includes(scope) || allowed.includes('*'));
        
        return validated.join(' ');
    }
}
```

### 5.3 Token Validation Service

```typescript
class TokenValidationService {
    constructor(
        private db: Database,
        private cryptoService: CryptoService,
        private config: {
            jwtPublicKey: string;
        }
    ) {}
    
    async validateToken(token: string): Promise<{
        active: boolean;
        scope?: string;
        exp?: number;
        sub?: string;
        toolDetails?: {
            tool_id: string;
            tool_version: string;
            tool_provider: string;
        };
    }> {
        try {
            // First, verify the JWT signature
            const isSignatureValid = await this.cryptoService.verifyJwt(
                token,
                this.config.jwtPublicKey
            );
            
            if (!isSignatureValid) {
                return { active: false };
            }
            
            // Decode the token (since signature is valid)
            const decoded = this.cryptoService.decodeJwt(token);
            
            // Check if token has expired
            const now = Math.floor(Date.now() / 1000);
            if (decoded.exp < now) {
                return { active: false };
            }
            
            // Check if token has been revoked
            const isRevoked = await this.db.isTokenRevoked(decoded.jti);
            if (isRevoked) {
                return { active: false };
            }
            
            // Check if issuer is valid
            if (decoded.iss !== 'etdi-oauth-idp') {
                return { active: false };
            }
            
            // Check if provider is still active
            const provider = await this.db.getProvider(decoded.sub);
            if (!provider || provider.status !== 'APPROVED') {
                return { active: false };
            }
            
            // Extract tool details if present
            const toolDetails = {
                tool_id: decoded.tool_id,
                tool_version: decoded.tool_version,
                tool_provider: decoded.tool_provider,
            };
            
            // All checks passed
            return {
                active: true,
                scope: decoded.scope,
                exp: decoded.exp,
                sub: decoded.sub,
                toolDetails: decoded.tool_id ? toolDetails : undefined,
            };
        } catch (error) {
            console.error(`Token validation error: ${error.message}`);
            return { active: false };
        }
    }
}
```

## 6. Cryptographic Services Implementation

### 6.1 Core Cryptographic Functions

```typescript
class CryptoService {
    // Generate a consistent hash for a given payload
    async hash(payload: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(payload);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        
        // Convert to hex string
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    // Sign data with a private key
    async sign(payload: string, privateKey: string, algorithm: string): Promise<string> {
        // Convert PEM private key to CryptoKey
        const cryptoKey = await this.importPrivateKey(privateKey, algorithm);
        
        // Encode the payload
        const encoder = new TextEncoder();
        const data = encoder.encode(payload);
        
        // Sign the payload
        const signatureBuffer = await crypto.subtle.sign(
            this.getAlgorithmParams(algorithm),
            cryptoKey,
            data
        );
        
        // Convert to base64
        return this.bufferToBase64(signatureBuffer);
    }
    
    // Verify a signature with a public key
    async verify(payload: string, signature: string, publicKey: string, algorithm: string): Promise<boolean> {
        // Convert PEM public key to CryptoKey
        const cryptoKey = await this.importPublicKey(publicKey, algorithm);
        
        // Encode the payload
        const encoder = new TextEncoder();
        const data = encoder.encode(payload);
        
        // Decode base64 signature
        const signatureBuffer = this.base64ToBuffer(signature);
        
        // Verify the signature
        return crypto.subtle.verify(
            this.getAlgorithmParams(algorithm),
            cryptoKey,
            signatureBuffer,
            data
        );
    }
    
    // Sign a JWT
    async signJwt(payload: object, privateKey: string, algorithm: string): Promise<string> {
        // Create JWT header
        const header = {
            alg: algorithm,
            typ: 'JWT',
        };
        
        // Encode header and payload
        const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
        const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
        
        // Create signature input
        const signatureInput = `${encodedHeader}.${encodedPayload}`;
        
        // Sign the input
        const signature = await this.sign(signatureInput, privateKey, algorithm);
        
        // Convert standard base64 to base64url
        const encodedSignature = this.base64ToBase64Url(signature);
        
        // Return complete JWT
        return `${signatureInput}.${encodedSignature}`;
    }
    
    // Verify a JWT
    async verifyJwt(token: string, publicKey: string): Promise<boolean> {
        // Split the token
        const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
        
        // Decode header to get algorithm
        const headerJson = this.base64UrlDecode(encodedHeader);
        const header = JSON.parse(headerJson);
        
        // Create signature input
        const signatureInput = `${encodedHeader}.${encodedPayload}`;
        
        // Convert base64url to standard base64
        const signature = this.base64UrlToBase64(encodedSignature);
        
        // Verify the signature
        return this.verify(signatureInput, signature, publicKey, header.alg);
    }
    
    // Decode a JWT without verification
    decodeJwt(token: string): any {
        const [_, encodedPayload] = token.split('.');
        const payloadJson = this.base64UrlDecode(encodedPayload);
        return JSON.parse(payloadJson);
    }
    
    // Generate a random ID
    async generateId(): Promise<string> {
        const buffer = new Uint8Array(16);
        crypto.getRandomValues(buffer);
        return Array.from(buffer)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    // Generate a random string
    async generateRandomString(length: number): Promise<string> {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const buffer = new Uint8Array(length);
        crypto.getRandomValues(buffer);
        
        return Array.from(buffer)
            .map(b => charset[b % charset.length])
            .join('');
    }
    
    // Helper methods for key import/export and format conversions
    // (Implementation details would depend on specific cryptographic libraries)
    private async importPrivateKey(pemKey: string, algorithm: string): Promise<CryptoKey> {
        // Implementation would convert PEM to crypto.subtle compatible format
        // This is a placeholder for actual implementation
        return {} as CryptoKey;
    }
    
    private async importPublicKey(pemKey: string, algorithm: string): Promise<CryptoKey> {
        // Implementation would convert PEM to crypto.subtle compatible format
        // This is a placeholder for actual implementation
        return {} as CryptoKey;
    }
    
    private getAlgorithmParams(algorithm: string): Algorithm {
        // Map algorithm string to WebCrypto algorithm parameters
        switch (algorithm) {
            case 'RS256':
                return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
            case 'ES256':
                return { name: 'ECDSA', hash: { name: 'SHA-256' }, namedCurve: 'P-256' };
            // Add other algorithms as needed
            default:
                throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
    }
    
    private bufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    private base64ToBuffer(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    private base64UrlEncode(str: string): string {
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    
    private base64UrlDecode(str: string): string {
        // Add back padding if needed
        str = str.padEnd(str.length + (4 - (str.length % 4)) % 4, '=');
        return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    }
    
    private base64ToBase64Url(base64: string): string {
        return base64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    
    private base64UrlToBase64(base64url: string): string {
        // Add back padding if needed
        let result = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const paddingLength = (4 - (result.length % 4)) % 4;
        return result + '='.repeat(paddingLength);
    }
}
```

## 7. Key Management Implementation

### 7.1 Key Distribution Service

```typescript
class KeyDistributionService {
    constructor(
        private db: Database,
        private cryptoService: CryptoService
    ) {}
    
    async getProviderPublicKey(providerId: string): Promise<{
        providerId: string;
        providerName: string;
        publicKey: string;
        keyId: string;
        algorithm: string;
        validFrom: Date;
        validUntil?: Date;
        revoked: boolean;
    }> {
        // Get provider information
        const provider = await this.db.getProvider(providerId);
        if (!provider) {
            throw new Error(`Provider not found: ${providerId}`);
        }
        
        // Get current active key
        const key = await this.db.getActivePublicKey(providerId);
        if (!key) {
            throw new Error(`No active key found for provider: ${providerId}`);
        }
        
        return {
            providerId: provider.id,
            providerName: provider.name,
            publicKey: key.publicKey,
            keyId: key.id,
            algorithm: key.algorithm,
            validFrom: key.validFrom,
            validUntil: key.validUntil,
            revoked: key.revoked,
        };
    }
    
    async getJwks(): Promise<{
        keys: Array<{
            kid: string;
            kty: string;
            use: string;
            alg: string;
            [key: string]: any; // Additional JWK parameters
        }>;
    }> {
        // Get all active IdP public keys
        const keys = await this.db.getAllActiveIdpKeys();
        
        // Convert to JWKS format
        const jwks = keys.map(key => {
            // Convert PEM to JWK
            const jwk = this.pemToJwk(key.publicKey, key.algorithm);
            
            return {
                kid: key.id,
                kty: this.getKeyType(key.algorithm),
                use: 'sig',
                alg: key.algorithm,
                ...jwk,
            };
        });
        
        return { keys: jwks };
    }
    
    private pemToJwk(pemKey: string, algorithm: string): any {
        // Implementation would convert PEM to JWK format
        // This is a placeholder for actual implementation
        return {};
    }
    
    private getKeyType(algorithm: string): string {
        if (algorithm.startsWith('RS')) return 'RSA';
        if (algorithm.startsWith('ES')) return 'EC';
        if (algorithm.startsWith('HS')) return 'oct';
        return 'RSA'; // Default
    }
}
```

### 7.2 Key Rotation Service

```typescript
class KeyRotationService {
    constructor(
        private db: Database,
        private cryptoService: CryptoService,
        private config: {
            keyValidityPeriod: number; // milliseconds
            keyAlgorithm: string;
        }
    ) {}
    
    async rotateIdpKeys(): Promise<void> {
        // Generate new key pair
        const { publicKey, privateKey } = await this.generateKeyPair(this.config.keyAlgorithm);
        
        // Create key ID
        const keyId = await this.cryptoService.generateId();
        
        // Set validity period
        const now = new Date();
        const validUntil = new Date(now.getTime() + this.config.keyValidityPeriod);
        
        // Store new keys
        await this.db.storeIdpKeyPair({
            id: keyId,
            publicKey,
            privateKey,
            algorithm: this.config.keyAlgorithm,
            validFrom: now,
            validUntil,
            revoked: false,
        });
        
        // Mark as active
        await this.db.setActiveIdpKey(keyId);
    }
    
    async rotateProviderKeys(providerId: string): Promise<{
        keyId: string;
        publicKey: string;
        privateKey: string;
    }> {
        // Check provider exists
        const provider = await this.db.getProvider(providerId);
        if (!provider) {
            throw new Error(`Provider not found: ${providerId}`);
        }
        
        // Generate new key pair
        const { publicKey, privateKey } = await this.generateKeyPair(provider.keyAlgorithm);
        
        // Create key ID
        const keyId = await this.cryptoService.generateId();
        
        // Set validity period
        const now = new Date();
        const validUntil = new Date(now.getTime() + this.config.keyValidityPeriod);
        
        // Store new keys
        await this.db.storeProviderKeyPair({
            id: keyId,
            providerId,
            publicKey,
            privateKey,
            algorithm: provider.keyAlgorithm,
            validFrom: now,
            validUntil,
            revoked: false,
        });
        
        // Mark as active
        await this.db.setActiveProviderKey(providerId, keyId);
        
        return {
            keyId,
            publicKey,
            privateKey,
        };
    }
    
    private async generateKeyPair(algorithm: string): Promise<{
        publicKey: string;
        privateKey: string;
    }> {
        // Implementation would generate keys based on algorithm
        // This is a placeholder for actual implementation
        return {
            publicKey: 'PEM-FORMATTED PUBLIC KEY',
            privateKey: 'PEM-FORMATTED PRIVATE KEY',
        };
    }
}
```

## 8. Performance Optimization

### 8.1 Caching Strategy

```typescript
class EtdiCache {
    private signatureCache: Map<string, {
        result: boolean;
        timestamp: number;
    }> = new Map();
    
    private publicKeyCache: Map<string, {
        key: string;
        timestamp: number;
    }> = new Map();
    
    private tokenValidationCache: Map<string, {
        result: { active: boolean; [key: string]: any };
        timestamp: number;
    }> = new Map();
    
    constructor(
        private config: {
            signatureCacheTtl: number; // milliseconds
            publicKeyCacheTtl: number; // milliseconds
            tokenValidationCacheTtl: number; // milliseconds
            maxCacheSize: number;
        }
    ) {}
    
    getCachedSignatureVerification(toolId: string, definitionHash: string): boolean | null {
        const key = `${toolId}:${definitionHash}`;
        const cached = this.signatureCache.get(key);
        
        if (!cached) return null;
        
        // Check if entry has expired
        if (Date.now() - cached.timestamp > this.config.signatureCacheTtl) {
            this.signatureCache.delete(key);
            return null;
        }
        
        return cached.result;
    }
    
    cacheSignatureVerification(toolId: string, definitionHash: string, result: boolean): void {
        // Enforce cache size limit with LRU eviction
        if (this.signatureCache.size >= this.config.maxCacheSize) {
            // Find oldest entry
            let oldestKey = '';
            let oldestTime = Infinity;
            
            for (const [key, value] of this.signatureCache.entries()) {
                if (value.timestamp < oldestTime) {
                    oldestTime = value.timestamp;
                    oldestKey = key;
                }
            }
            
            // Evict oldest entry
            if (oldestKey) {
                this.signatureCache.delete(oldestKey);
            }
        }
        
        const key = `${toolId}:${definitionHash}`;
        this.signatureCache.set(key, {
            result,
            timestamp: Date.now(),
        });
    }
    
    // Similar methods for public key caching and token validation caching
    // ...
    
    clearCache(): void {
        this.signatureCache.clear();
        this.publicKeyCache.clear();
        this.tokenValidationCache.clear();
    }
}
```

### 8.2 Parallel Verification

```typescript
class ParallelVerificationService {
    constructor(
        private etdiClient: ETDIClient,
        private maxConcurrent: number = 5
    ) {}
    
    async verifyMultipleTools(tools: ETDIToolDefinition[]): Promise<Map<string, boolean>> {
        const results = new Map<string, boolean>();
        
        // Process tools in batches to limit concurrency
        for (let i = 0; i < tools.length; i += this.maxConcurrent) {
            const batch = tools.slice(i, i + this.maxConcurrent);
            
            // Verify batch in parallel
            const verificationPromises = batch.map(async tool => {
                try {
                    const isVerified = await this.etdiClient.verifyToolSignature(tool);
                    results.set(tool.id, isVerified);
                } catch (error) {
                    console.error(`Error verifying tool ${tool.id}: ${error.message}`);
                    results.set(tool.id, false);
                }
            });
            
            // Wait for all verifications in this batch to complete
            await Promise.all(verificationPromises);
        }
        
        return results;
    }
}
```

## 9. Backward Compatibility

### 9.1 MCP Protocol Extension

```typescript
class BackwardCompatibilityManager {
    constructor(
        private config: {
            etdiRequired: boolean;
            showUnverifiedWarning: boolean;
        }
    ) {}
    
    modifyMcpProtocolHandshake(clientCapabilities: any, serverCapabilities: any): {
        clientCapabilities: any;
        serverCapabilities: any;
    } {
        // Add ETDI capability to client
        const enhancedClientCapabilities = {
            ...clientCapabilities,
            extensions: {
                ...(clientCapabilities.extensions || {}),
                etdi: {
                    version: '1.0',
                    required: this.config.etdiRequired,
                    supportedAlgorithms: ['RS256', 'ES256'],
                    supportedOAuthFlows: ['client_credentials'],
                },
            },
        };
        
        // Add ETDI capability to server response if supported
        let enhancedServerCapabilities = serverCapabilities;
        
        if (serverCapabilities.extensions?.etdi) {
            // Server already supports ETDI
            enhancedServerCapabilities = serverCapabilities;
        } else {
            // Server doesn't explicitly support ETDI
            // If ETDI is required by client, we might need to handle this case
            if (this.config.etdiRequired) {
                console.warn('Server does not support required ETDI extension');
            }
        }
        
        return {
            clientCapabilities: enhancedClientCapabilities,
            serverCapabilities: enhancedServerCapabilities,
        };
    }
    
    handleMixedToolset(verifiedTools: ETDIToolDefinition[], unverifiedTools: any[]): {
        combinedTools: any[];
        recommendations: string[];
    } {
        const recommendations: string[] = [];
        
        // Only when we're showing unverified tools
        if (!this.config.etdiRequired) {
            if (unverifiedTools.length > 0) {
                recommendations.push(
                    'Some tools are not ETDI-verified. Consider enabling strict mode for enhanced security.'
                );
            }
        }
        
        // Mark unverified tools
        const markedUnverifiedTools = unverifiedTools.map(tool => ({
            ...tool,
            etdi_status: 'UNVERIFIED',
            name: this.config.showUnverifiedWarning ? `⚠️ ${tool.name} (UNVERIFIED)` : tool.name,
        }));
        
        // Mark verified tools
        const markedVerifiedTools = verifiedTools.map(tool => ({
            ...tool,
            etdi_status: 'VERIFIED',
        }));
        
        // Combine tools with verified ones first
        const combinedTools = [...markedVerifiedTools, ...markedUnverifiedTools];
        
        return {
            combinedTools,
            recommendations,
        };
    }
}
```

### 9.2 Tool Provider Migration Utility

```typescript
class ToolProviderMigrationUtility {
    constructor(
        private toolRegistry: ETDIToolRegistry,
        private cryptoService: CryptoService,
        private keyRotationService: KeyRotationService
    ) {}
    
    async migrateExistingTool(
        legacyToolDefinition: any,
        providerDetails: {
            name: string;
            id?: string; // Optional, generated if not provided
            website: string;
            contactEmail: string;
        }
    ): Promise<{
        etdiToolDefinition: ETDIToolDefinition;
        providerId: string;
        publicKey: string;
        privateKey: string;
    }> {
        // Generate or use provider ID
        const providerId = providerDetails.id || await this.cryptoService.generateId();
        
        // Generate key pair for the provider
        const { keyId, publicKey, privateKey } = 
            await this.keyRotationService.rotateProviderKeys(providerId);
        
        // Map legacy permissions to ETDI permissions
        const mappedPermissions = this.mapLegacyPermissions(legacyToolDefinition.permissions);
        
        // Create ETDI tool definition
        const etdiToolDefinition: Omit<ETDIToolDefinition, 'signature' | 'provider' | 'signatureAlgorithm'> = {
            id: legacyToolDefinition.id || await this.cryptoService.generateId(),
            name: legacyToolDefinition.name,
            version: legacyToolDefinition.version || '1.0.0', // Default to 1.0.0 if not present
            description: legacyToolDefinition.description,
            schema: legacyToolDefinition.schema,
            permissions: mappedPermissions,
        };
        
        // Register tool with ETDI
        const registeredTool = await this.toolRegistry.registerTool(etdiToolDefinition);
        
        return {
            etdiToolDefinition: registeredTool,
            providerId,
            publicKey,
            privateKey,
        };
    }
    
    private mapLegacyPermissions(legacyPermissions: any): Permission[] {
        // Implementation depends on the legacy permission format
        // This is a placeholder for actual mapping logic
        const mappedPermissions: Permission[] = [];
        
        // Example mapping
        if (legacyPermissions?.filesystem?.read) {
            mappedPermissions.push('filesystem:read:/');
        }
        
        if (legacyPermissions?.network?.access) {
            mappedPermissions.push('network:access:*');
        }
        
        return mappedPermissions;
    }
}
```

## 10. Deployment and Configuration

### 10.1 ETDI Configuration Options

```typescript
interface ETDIConfiguration {
    // Security settings
    security: {
        strictMode: boolean;                     // Require ETDI for all tools
        allowUnverifiedTools: boolean;           // Allow tools without signatures
        warningForUnverifiedTools: boolean;      // Add warning to unverified tool names
        requiredSignatureAlgorithms: string[];   // List of acceptable signature algorithms
    };
    
    // OAuth settings
    oauth: {
        enabled: boolean;                        // Use OAuth enhanced ETDI
        preferOAuthOverDirectSignatures: boolean;// Prefer OAuth tokens when both are present
        trustedIdPs: {                           // List of trusted Identity Providers
            [idpId: string]: {
                name: string;                    // Human-readable name
                jwksUri: string;                 // URI for JWKS (public keys)
                tokenIntrospectionEndpoint?: string; // Optional endpoint for token introspection
            };
        };
        clientId?: string;                       // Client ID for this MCP client
        clientSecret?: string;                   // Client secret for token introspection
    };
    
    // Provider trust settings
    providerTrust: {
        trustedProviders: {                      // List of trusted providers
            [providerId: string]: {
                name: string;                    // Human-readable name
                publicKeyPem: string;            // PEM-encoded public key
                keyId: string;                   // Key identifier
            };
        };
        autoTrustFromRegistry: boolean;          // Automatically trust providers from registry
        registryUrl?: string;                    // URL of provider registry
    };
    
    // Performance settings
    performance: {
        enableCaching: boolean;                  // Enable caching of verification results
        cacheTtl: number;                        // Time-to-live for cache entries (ms)
        maxCacheSize: number;                    // Maximum number of cached entries
        parallelVerification: boolean;           // Enable parallel verification of multiple tools
        maxConcurrentVerifications: number;      // Maximum concurrent verifications
    };
    
    // Storage settings
    storage: {
        approvalStorageLocation: string;         // Where to store approval records
        encryptApprovalRecords: boolean;         // Whether to encrypt stored approvals
        encryptionKey?: string;                  // Key for encryption (if enabled)
    };
}
```

### 10.2 Sample Implementation in existing MCP flows

```typescript
class MCP {
    async initialize() {
        // Existing MCP initialization code
        // ...
        
        // Initialize ETDI components if enabled
        if (this.config.extensions?.etdi?.enabled) {
            await this.initializeETDI();
        }
    }
    
    async listTools() {
        // Get tools using standard MCP
        const tools = await this.standardListTools();
        
        // If ETDI is enabled, verify tools
        if (this.etdiEnabled) {
            return this.etdiClient.verifyToolList(tools);
        }
        
        return tools;
    }
    
    async invokeTool(toolId, params) {
        // If ETDI is enabled, perform verification before invocation
        if (this.etdiEnabled) {
            const tool = await this.getTool(toolId);
            const verificationResult = await this.etdiClient.checkToolBeforeInvocation(tool);
            
            if (!verificationResult.canProceed) {
                if (verificationResult.requiresReapproval) {
                    throw new Error(`Tool requires re-approval: ${verificationResult.reason}`);
                } else {
                    throw new Error(`Tool verification failed: ${verificationResult.reason}`);
                }
            }
        }
        
        // Proceed with standard invocation
        return this.standardInvokeTool(toolId, params);
    }
    
    private async initializeETDI() {
        // Create crypto service
        this.cryptoService = new CryptoService();
        
        // Create key store
        this.keyStore = new KeyStore(this.config.etdi.providerTrust);
        
        // Create OAuth client if enabled
        if (this.config.etdi.oauth.enabled) {
            this.oauthClient = new OAuthClientModule(this.config.etdi.oauth);
        }
        
        // Create ETDI client
        this.etdiClient = new ETDIClient(
            this.cryptoService,
            this.keyStore,
            this.oauthClient,
            this.config.etdi
        );
        
        this.etdiEnabled = true;
    }
}
```

## 11. Testing Strategy

### 11.1 Key Security Tests

1. **Tool Poisoning Prevention Test**
   - Create a legitimate tool with proper signatures
   - Create a malicious tool mimicking the legitimate one
   - Verify that the client correctly identifies and rejects the malicious tool

2. **Rug Pull Prevention Test**
   - Approve a tool with version 1.0.0
   - Attempt to modify the tool's behavior without changing version
   - Verify that the client detects the change and requires re-approval

3. **OAuth Token Validation Test**
   - Create valid OAuth tokens for tools
   - Create expired tokens, tokens with invalid signatures, and tokens with insufficient scopes
   - Verify that only valid tokens with appropriate scopes are accepted

4. **Backward Compatibility Test**
   - Test interaction between ETDI-enabled clients and non-ETDI servers
   - Test interaction between ETDI-enabled servers and non-ETDI clients
   - Verify graceful degradation and appropriate warnings

### 11.2 Performance Tests

1. **Verification Overhead Test**
   - Measure tool discovery time with and without ETDI verification
   - Benchmark tool invocation with and without ETDI verification
   - Test with various numbers of tools to assess scaling

2. **Caching Effectiveness Test**
   - Measure verification times with cold and warm caches
   - Test cache invalidation scenarios
   - Measure memory usage under various cache sizes

3. **Network Latency Impact Test**
   - Simulate various network conditions for OAuth token validation
   - Test offline capabilities with cached public keys
   - Measure timeout and retry behavior

## 12. Implementation Roadmap

1. **Phase 1: Core ETDI Implementation**
   - Implement cryptographic services
   - Implement key management
   - Modify MCP Client for signature verification
   - Modify MCP Server for tool signing

2. **Phase 2: OAuth Integration**
   - Implement Identity Provider components
   - Implement OAuth client in MCP Client
   - Implement OAuth integration in MCP Server
   - Create provider registration workflow

3. **Phase 3: Migration and Backward Compatibility**
   - Implement migration utilities for existing tools
   - Add backward compatibility layers
   - Create transition documentation for providers

4. **Phase 4: Performance Optimization**
   - Implement caching strategies
   - Add parallel verification
   - Optimize cryptographic operations

5. **Phase 5: Security Hardening**
   - Conduct security audits
   - Implement additional security measures based on findings
   - Create incident response procedures