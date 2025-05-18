# Getting Started with ETDI

This guide will help you get started with implementing ETDI in your application.

## Prerequisites

- For TypeScript:
  - Node.js 16.x or later
  - TypeScript 4.x or later
  - npm or yarn package manager
- For Python:
  - Python 3.9 or later
  - pip or poetry package manager
- Basic understanding of OAuth 2.0

## Installation

### TypeScript

```bash
npm install @etdi/sdk
# or
yarn add @etdi/sdk
```

Dependencies:

```bash
npm install @etdi/oauth @etdi/crypto
# or
yarn add @etdi/oauth @etdi/crypto
```

### Python

```bash
pip install etdi
# or
poetry add etdi
```

## Basic Implementation

### TypeScript

#### 1. Initialize ETDI Client

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

#### 2. Configure Tool Provider

```typescript
import { ToolProvider } from '@etdi/sdk';

const provider = new ToolProvider({
  name: 'MyToolProvider',
  version: '1.0.0',
  publicKey: 'your-public-key',
  privateKey: 'your-private-key'
});
```

#### 3. Define a Tool

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

### Python

#### 1. Initialize ETDI Client

```python
from etdi import ETDIClient

client = ETDIClient(
    security_level="enhanced",  # 'basic', 'enhanced', or 'strict'
    oauth_config={
        "provider": "auth0",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "domain": "your-auth0-domain"
    }
)
```

#### 2. Configure Tool Provider

```python
from etdi import ToolProvider

provider = ToolProvider(
    name="MyToolProvider",
    version="1.0.0",
    public_key="your-public-key",
    private_key="your-private-key"
)
```

#### 3. Define a Tool

```python
from etdi import ToolDefinition, Permission

tool_definition = ToolDefinition(
    id="my-tool",
    name="My Tool",
    version="1.0.0",
    description="A sample tool implementation",
    provider={
        "id": provider.id,
        "name": provider.name
    },
    permissions=[
        Permission(
            name="read:data",
            description="Read data from the system",
            scope="read:data",
            required=True
        ),
        Permission(
            name="write:data",
            description="Write data to the system",
            scope="write:data",
            required=False
        )
    ],
    schema={
        # JSON Schema for tool input/output
    }
)
```

## Working with Tool Registration and Verification

### TypeScript

```typescript
// Register tool with provider
const signedTool = await provider.registerTool(toolDefinition);

// Verify tool signature
const isValid = await client.verifyTool(signedTool);

// Discover available tools
const tools = await client.discoverTools();

// Filter and verify tools
const verifiedTools = tools.filter(tool => tool.verificationStatus === 'VERIFIED');

// Request tool usage
const result = await client.invokeTool('my-tool', {
  // Tool parameters
});
```

### Python

```python
# Register tool with provider
signed_tool = await provider.register_tool(tool_definition)

# Verify tool signature
is_valid = await client.verify_tool(signed_tool)

# Discover available tools
tools = await client.discover_tools()

# Filter and verify tools
verified_tools = []
for tool in tools:
    if await client.verify_tool(tool):
        verified_tools.append(tool)

# Request tool usage
result = await client.invoke_tool("my-tool", {
    # Tool parameters
})
```

## Integration with Anthropic

ETDI provides robust security extensions for the [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/), which can be integrated with Anthropic Claude models.

### TypeScript Integration

To integrate with Anthropic in TypeScript:

```typescript
import { ETDIClient } from '@etdi/sdk';
import { AnthropicMCPClient } from '@anthropic/mcp-client';

// Initialize ETDI client
const etdiClient = new ETDIClient({
  securityLevel: 'enhanced',
  oauthConfig: {
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain'
  }
});

// Initialize Anthropic client
const anthropicClient = new AnthropicMCPClient({
  apiKey: 'your-anthropic-api-key',
  model: 'claude-3-opus-20240229'
});

// Example: Register and secure an Anthropic MCP tool
async function setupSecureTool() {
  // Discover and verify tools
  const tools = await etdiClient.discoverTools();
  const verifiedTools = [];
  
  for (const tool of tools) {
    if (await etdiClient.verifyTool(tool)) {
      verifiedTools.push(tool);
    }
  }
  
  // Convert ETDI tools to MCP format for Anthropic
  const mcpTools = verifiedTools.map(tool => ({
    name: tool.id,
    description: tool.description,
    input_schema: tool.schema
  }));
  
  // Use the tools with Anthropic
  const message = await anthropicClient.messages.create({
    model: 'claude-3-opus-20240229',
    max_tokens: 1000,
    messages: [{ role: 'user', content: 'Please help me analyze this data.' }],
    tools: mcpTools
  });
  
  // Handle tool calls from Anthropic
  for (const toolCall of message.tool_calls || []) {
    if (toolCall.type === 'tool_call') {
      const tool = verifiedTools.find(t => t.id === toolCall.name);
      
      if (tool && await etdiClient.isToolApproved(tool.id)) {
        // Execute the tool through ETDI's secure channel
        const result = await etdiClient.invokeTool(
          tool.id, 
          JSON.parse(toolCall.params)
        );
        
        // Send result back to Anthropic
        // ...
      }
    }
  }
}
```

### Python Integration

To integrate with Anthropic in Python:

```python
from etdi import ETDIClient
from mcp import ClientSession
from mcp.client.stdio import stdio_client
import anthropic
import json

# Initialize ETDI client
etdi_client = ETDIClient(
    security_level="enhanced",
    oauth_config={
        "provider": "auth0",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "domain": "your-auth0-domain"
    }
)

# Initialize Anthropic client
anthropic_client = anthropic.Anthropic(
    api_key="your-anthropic-api-key"
)

# Example: Set up secure tools with Anthropic
async def setup_secure_tools():
    # Discover and verify tools
    tools = await etdi_client.discover_tools()
    verified_tools = []
    
    for tool in tools:
        if await etdi_client.verify_tool(tool):
            if not await etdi_client.is_tool_approved(tool.id):
                await etdi_client.approve_tool(tool)
            verified_tools.append(tool)
    
    # Convert ETDI tools to Anthropic tool format
    anthropic_tools = []
    for tool in verified_tools:
        anthropic_tools.append({
            "name": tool.id,
            "description": tool.description,
            "input_schema": tool.schema
        })
    
    # Use tools with Anthropic
    message = anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1000,
        messages=[{"role": "user", "content": "Please help me analyze this data."}],
        tools=anthropic_tools
    )
    
    # Handle tool calls from Anthropic
    for tool_call in message.content:
        if hasattr(tool_call, "type") and tool_call.type == "tool_use":
            tool = next((t for t in verified_tools if t.id == tool_call.name), None)
            
            if tool and await etdi_client.is_tool_approved(tool.id):
                # Execute the tool through ETDI's secure channel
                result = await etdi_client.invoke_tool(
                    tool.id,
                    json.loads(tool_call.input)
                )
                
                # Send result back to Anthropic
                # ...
```

## Security Implementation

### OAuth Integration

For both TypeScript and Python:

1. Configure OAuth providers
2. Implement token verification
3. Manage permissions and scopes

See the [OAuth Integration Guide](oauth-integration.md) for detailed implementation steps.

## Next Steps

1. Review the [OAuth Integration Guide](oauth-integration.md) for detailed OAuth implementation
2. Check the [Best Practices](best-practices.md) for implementation recommendations
3. Explore the SDK documentation:
   - [TypeScript SDK Documentation](../development/typescript-sdk.md)
   - [Python SDK Documentation](../development/python-sdk.md)
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