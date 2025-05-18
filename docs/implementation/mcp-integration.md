# Integrating ETDI with Model Context Protocol

This guide provides detailed instructions on integrating the Enhanced Tool Definition Interface (ETDI) security extensions with the Model Context Protocol (MCP). You'll learn which specific classes to extend and what files to modify in both TypeScript and Python implementations.

## Overview

ETDI enhances MCP by adding:
- Cryptographic verification for tool definitions
- Immutable versioned definitions
- Explicit permission management
- OAuth integration for identity verification

## TypeScript Integration

### Required Files

When integrating ETDI with the TypeScript MCP SDK, you'll need to modify or extend the following files:

| Purpose | Base MCP File | Implementation Approach |
|---------|--------------|------------------------|
| Client Extension | `@mcp/client` | Extend `MCPClient` class to add ETDI verification |
| Tool Definition | `@mcp/types` | Extend `Tool` interface with ETDI security properties |
| Session Management | `@mcp/session` | Wrap `ClientSession` with ETDI verification layer |

### Extending Core Classes

#### 1. Extending MCP Client

Create a secure client that wraps the MCP client with ETDI verification:

```typescript
// Path: src/ETDISecureMCPClient.ts
import { MCPClient, MCPClientOptions } from '@mcp/client';
import { ETDIClient, ToolDefinition } from '@etdi/sdk';

export class ETDISecureMCPClient extends MCPClient {
  private etdiClient: ETDIClient;
  
  constructor(
    mcpOptions: MCPClientOptions, 
    etdiOptions: {
      securityLevel: 'basic' | 'enhanced' | 'strict';
      oauthConfig?: any;
    }
  ) {
    super(mcpOptions);
    
    // Initialize ETDI client
    this.etdiClient = new ETDIClient({
      securityLevel: etdiOptions.securityLevel,
      oauthConfig: etdiOptions.oauthConfig
    });
  }
  
  // Override the listTools method to add verification
  async listTools() {
    const tools = await super.listTools();
    const verifiedTools = [];
    
    for (const tool of tools) {
      // Convert MCP tool to ETDI tool format
      const etdiTool: ToolDefinition = {
        id: tool.name,
        name: tool.name,
        version: tool.version || '1.0.0',
        description: tool.description,
        provider: {
          id: tool.provider?.id || 'unknown',
          name: tool.provider?.name || 'unknown'
        },
        schema: tool.parameters || {},
        permissions: []
      };
      
      // Verify tool
      const isVerified = await this.etdiClient.verifyTool(etdiTool);
      
      if (isVerified) {
        verifiedTools.push(tool);
      }
    }
    
    return verifiedTools;
  }
  
  // Override callTool method to add security checks
  async callTool(name: string, parameters: any) {
    // Check if tool is approved
    const isApproved = await this.etdiClient.isToolApproved(name);
    
    if (!isApproved) {
      throw new Error(`Tool '${name}' is not approved for use`);
    }
    
    // Check version changes
    const versionChanged = await this.etdiClient.checkVersionChange(name);
    
    if (versionChanged) {
      throw new Error(`Tool '${name}' version has changed and requires re-approval`);
    }
    
    // Call the tool through MCP after verification
    return super.callTool(name, parameters);
  }
}
```

#### 2. Creating a Secure Session Manager

```typescript
// Path: src/ETDISecureSession.ts
import { ClientSession } from '@mcp/session';
import { ReadableStream, WritableStream } from 'stream/web';
import { ETDIClient } from '@etdi/sdk';

export class ETDISecureSession {
  private session: ClientSession;
  private etdiClient: ETDIClient;
  
  constructor(
    readStream: ReadableStream,
    writeStream: WritableStream,
    etdiOptions: {
      securityLevel: 'basic' | 'enhanced' | 'strict';
      oauthConfig?: any;
    }
  ) {
    this.session = new ClientSession(readStream, writeStream);
    
    // Initialize ETDI client
    this.etdiClient = new ETDIClient({
      securityLevel: etdiOptions.securityLevel,
      oauthConfig: etdiOptions.oauthConfig
    });
  }
  
  async initialize() {
    await this.session.initialize();
  }
  
  async listTools() {
    const tools = await this.session.listTools();
    const verifiedTools = [];
    
    for (const tool of tools) {
      // Convert to ETDI format and verify
      const isVerified = await this.convertAndVerify(tool);
      
      if (isVerified) {
        verifiedTools.push(tool);
      }
    }
    
    return verifiedTools;
  }
  
  async callTool(name: string, arguments: any) {
    // Check approval and security before calling
    const isApproved = await this.etdiClient.isToolApproved(name);
    
    if (!isApproved) {
      throw new Error(`Tool '${name}' is not approved for use`);
    }
    
    return this.session.callTool(name, arguments);
  }
  
  private async convertAndVerify(mcpTool: any) {
    // Implement conversion and verification logic
    // ...
  }
  
  // Other session methods with security checks...
}
```

## Python Integration

### Required Files

When integrating ETDI with the Python MCP SDK, you'll need to modify or extend the following files:

| Purpose | Base MCP File | Implementation Approach |
|---------|--------------|------------------------|
| Client Session | `mcp/ClientSession` | Subclass to add ETDI verification |
| Tool Definition | `mcp/types` | Extend with ETDI security properties |
| Server Security | `mcp/server` | Add verification middleware to server |

### Extending Core Classes

#### 1. Creating a Secure Client Session

```python
# Path: etdi_mcp/secure_session.py
from mcp import ClientSession
from etdi import ETDIClient

class ETDISecureClientSession(ClientSession):
    """Secure MCP client session with ETDI verification."""
    
    def __init__(self, read_stream, write_stream, etdi_config=None, **kwargs):
        super().__init__(read_stream, write_stream, **kwargs)
        
        # Initialize ETDI client
        self.etdi_client = ETDIClient(
            security_level=etdi_config.get("security_level", "enhanced"),
            oauth_config=etdi_config.get("oauth_config")
        )
    
    async def list_tools(self):
        """Override to add verification."""
        tools = await super().list_tools()
        verified_tools = []
        
        for tool in tools:
            # Convert MCP tool to ETDI format
            etdi_tool = self._convert_to_etdi_format(tool)
            
            # Verify tool
            is_verified = await self.etdi_client.verify_tool(etdi_tool)
            
            if is_verified:
                is_approved = await self.etdi_client.is_tool_approved(tool.name)
                if not is_approved:
                    # In a real implementation, you might prompt for approval here
                    await self.etdi_client.approve_tool(etdi_tool)
                verified_tools.append(tool)
        
        return verified_tools
    
    async def call_tool(self, name, arguments=None):
        """Override to add security checks."""
        # Check if tool is approved
        is_approved = await self.etdi_client.is_tool_approved(name)
        
        if not is_approved:
            raise ValueError(f"Tool '{name}' is not approved for use")
        
        # Check for version changes
        version_changed = await self.etdi_client.check_version_change(name)
        
        if version_changed:
            raise ValueError(f"Tool '{name}' version has changed and requires re-approval")
        
        # Call the tool after verification
        return await super().call_tool(name, arguments)
    
    def _convert_to_etdi_format(self, mcp_tool):
        """Convert MCP tool to ETDI format."""
        from etdi import ToolDefinition, Permission
        
        # Extract provider information
        provider_info = getattr(mcp_tool, "provider", {}) or {}
        
        return ToolDefinition(
            id=mcp_tool.name,
            name=mcp_tool.name,
            version=getattr(mcp_tool, "version", "1.0.0"),
            description=mcp_tool.description,
            provider={
                "id": provider_info.get("id", "unknown"),
                "name": provider_info.get("name", "unknown")
            },
            schema=getattr(mcp_tool, "parameters", {}),
            permissions=[]  # Add permissions as needed
        )
```

#### 2. Securing MCP Server

```python
# Path: etdi_mcp/secure_server.py
from mcp.server import Server
from mcp.server.fastmcp import FastMCP
from etdi import ToolProvider

class ETDISecureServer(Server):
    """MCP server with ETDI security extensions."""
    
    def __init__(self, name, etdi_provider_config=None, **kwargs):
        super().__init__(name, **kwargs)
        
        # Initialize ETDI tool provider
        self.tool_provider = ToolProvider(
            name=etdi_provider_config.get("name", name),
            version=etdi_provider_config.get("version", "1.0.0"),
            public_key=etdi_provider_config.get("public_key"),
            private_key=etdi_provider_config.get("private_key")
        )
    
    def tool(self, **kwargs):
        """Override to add signature."""
        original_decorator = super().tool(**kwargs)
        
        def secure_decorator(func):
            # Apply the original decorator
            tool_func = original_decorator(func)
            
            # Register and sign the tool with ETDI
            from etdi import ToolDefinition
            
            # Create tool definition from function
            tool_def = ToolDefinition(
                id=func.__name__,
                name=func.__name__,
                version="1.0.0",
                description=func.__doc__ or "",
                provider={
                    "id": self.tool_provider.id,
                    "name": self.tool_provider.name
                },
                schema={
                    # Extract schema from function signature
                    # ...
                },
                permissions=[]  # Add permissions as needed
            )
            
            # Register and sign the tool
            self.tool_provider.register_tool(tool_def)
            
            return tool_func
        
        return secure_decorator

# Easy-to-use FastMCP extension
class ETDISecureFastMCP(FastMCP):
    """FastMCP with ETDI security extensions."""
    
    def __init__(self, name, etdi_provider_config=None, **kwargs):
        super().__init__(name, **kwargs)
        
        # Initialize ETDI tool provider
        self.tool_provider = ToolProvider(
            name=etdi_provider_config.get("name", name),
            version=etdi_provider_config.get("version", "1.0.0"),
            public_key=etdi_provider_config.get("public_key"),
            private_key=etdi_provider_config.get("private_key")
        )
    
    def tool(self, **kwargs):
        """Override to add signature."""
        # Similar implementation as above...
```

## Implementation Examples

### TypeScript: Using Secure MCP Client with Anthropic

```typescript
// Path: src/anthropic-integration.ts
import { ETDISecureMCPClient } from './ETDISecureMCPClient';
import { AnthropicClient } from '@anthropic-ai/sdk';

async function main() {
  // Initialize secure MCP client
  const secureMCP = new ETDISecureMCPClient(
    {
      // MCP options
      baseUrl: 'https://api.example.com/mcp',
      apiKey: 'your-mcp-api-key'
    },
    {
      // ETDI options
      securityLevel: 'enhanced',
      oauthConfig: {
        provider: 'auth0',
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        domain: 'your-auth0-domain'
      }
    }
  );
  
  // Get verified tools
  const verifiedTools = await secureMCP.listTools();
  
  // Initialize Anthropic client
  const anthropic = new AnthropicClient({
    apiKey: process.env.ANTHROPIC_API_KEY
  });
  
  // Format tools for Anthropic
  const anthropicTools = verifiedTools.map(tool => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.parameters
  }));
  
  // Use tools with Anthropic
  const message = await anthropic.messages.create({
    model: 'claude-3-opus-20240229',
    max_tokens: 1000,
    messages: [{
      role: 'user',
      content: 'I need to analyze some data'
    }],
    tools: anthropicTools
  });
  
  // Handle tool calls
  for (const content of message.content) {
    if (content.type === 'tool_use') {
      const result = await secureMCP.callTool(
        content.name,
        JSON.parse(content.input)
      );
      
      // Continue conversation with tool results
      // ...
    }
  }
}
```

### Python: Implementing a Secure MCP Server

```python
# Path: example_server.py
from etdi_mcp.secure_server import ETDISecureFastMCP

# Initialize secure MCP server
mcp = ETDISecureFastMCP(
    "Secure Data Service",
    etdi_provider_config={
        "name": "DataProvider",
        "version": "1.0.0",
        "public_key": "your-public-key",
        "private_key": "your-private-key"
    }
)

# Define secure resources and tools
@mcp.resource("data://{dataset_id}")
def get_dataset(dataset_id: str) -> str:
    """Securely retrieve a dataset by ID."""
    # Implementation...
    return f"Data for dataset {dataset_id}"

@mcp.tool()
def analyze_data(dataset_id: str, analysis_type: str) -> dict:
    """Run secure data analysis."""
    # Implementation...
    return {
        "dataset": dataset_id,
        "analysis_type": analysis_type,
        "results": [1, 2, 3, 4, 5]
    }

# Run the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(mcp.app, host="0.0.0.0", port=8000)
```

## Important Security Considerations

When integrating ETDI with MCP:

1. **Key Management**: Securely manage cryptographic keys used for signing tools
2. **Permission Mapping**: Clearly map MCP tool capabilities to ETDI permissions
3. **Version Tracking**: Implement robust version tracking for tools
4. **OAuth Configuration**: Properly configure OAuth providers for identity verification
5. **Audit Logging**: Add comprehensive logging for security events

## Deployment Considerations

For production deployments:

1. Use secure communication channels (HTTPS)
2. Implement rate limiting for API endpoints
3. Configure proper CORS settings for web clients
4. Use environment variables for sensitive configuration
5. Implement robust error handling and reporting

## Further Resources

- [TypeScript SDK Documentation](../development/typescript-sdk.md)
- [Python SDK Documentation](../development/python-sdk.md)
- [MCP Documentation](https://github.com/modelcontextprotocol/python-sdk)
- [OAuth Integration Guide](oauth-integration.md) 