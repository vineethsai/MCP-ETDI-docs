# Python SDK Documentation

This document provides detailed information about the ETDI Python SDK.

## Installation

```bash
pip install etdi
# or
poetry add etdi
```

## Core Components

### ETDIClient

The `ETDIClient` is the main entry point for applications using ETDI.

```python
from etdi import ETDIClient

client = ETDIClient(
    security_level="enhanced",
    oauth_config={
        "provider": "auth0",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "domain": "your-auth0-domain"
    }
)
```

#### Configuration Options

```python
class ETDIClientConfig:
    # Security level to use (basic, enhanced, or strict)
    security_level: Literal["basic", "enhanced", "strict"]
    
    # OAuth configuration (required for enhanced and strict)
    oauth_config: Optional[OAuthConfig] = None
    
    # Cryptographic key configuration (required for basic)
    key_config: Optional[KeyConfig] = None
    
    # Storage configuration for approvals and signatures
    storage_config: Optional[StorageConfig] = None
    
    # Options for timeout, retry, and caching
    options: Optional[ClientOptions] = None
```

#### Methods

```python
class ETDIClient:
    # Discover available tools from connected servers
    async def discover_tools(self) -> List[ToolDefinition]:
        ...
    
    # Verify a tool's signature
    async def verify_tool(self, tool: ToolDefinition) -> bool:
        ...
    
    # Approve a tool for usage
    async def approve_tool(self, tool: ToolDefinition) -> None:
        ...
    
    # Check if a tool has been approved
    async def is_tool_approved(self, tool_id: str) -> bool:
        ...
    
    # Invoke a tool with parameters
    async def invoke_tool(self, tool_id: str, params: Any) -> Any:
        ...
    
    # Check for tool version changes
    async def check_version_change(self, tool_id: str) -> bool:
        ...
    
    # Request re-approval for a tool
    async def request_reapproval(self, tool_id: str) -> None:
        ...
```

### ToolProvider

The `ToolProvider` is used by tool developers to create and register tools.

```python
from etdi import ToolProvider

provider = ToolProvider(
    name="MyToolProvider",
    version="1.0.0",
    public_key="your-public-key",
    private_key="your-private-key"
)
```

#### Methods

```python
class ToolProvider:
    # Register a new tool
    async def register_tool(self, definition: ToolDefinition) -> SignedToolDefinition:
        ...
    
    # Update an existing tool
    async def update_tool(self, tool_id: str, definition: ToolDefinition) -> SignedToolDefinition:
        ...
    
    # Get a list of registered tools
    async def get_tools(self) -> List[SignedToolDefinition]:
        ...
    
    # Remove a tool
    async def remove_tool(self, tool_id: str) -> bool:
        ...
```

### OAuthManager

The `OAuthManager` handles OAuth-related operations.

```python
from etdi import OAuthManager

manager = OAuthManager(
    provider="auth0",
    client_id="your-client-id",
    client_secret="your-client-secret",
    domain="your-auth0-domain"
)
```

#### Methods

```python
class OAuthManager:
    # Initialize the manager
    async def initialize(self) -> None:
        ...
    
    # Get a token
    async def get_token(self) -> str:
        ...
    
    # Validate a token
    async def validate_token(self, token: str) -> bool:
        ...
    
    # Refresh a token
    async def refresh_token(self, token: str) -> str:
        ...
    
    # Check if the token has specified scopes
    async def has_scopes(self, scopes: List[str]) -> bool:
        ...
    
    # Request additional scopes
    async def request_scopes(self, scopes: List[str]) -> str:
        ...
```

## Data Types

### ToolDefinition

```python
@dataclass
class ToolDefinition:
    # Unique identifier for the tool
    id: str
    
    # Human-readable name
    name: str
    
    # Semantic version (MAJOR.MINOR.PATCH)
    version: str
    
    # Human-readable description
    description: str
    
    # Provider information
    provider: Dict[str, str]
    
    # JSON Schema defining input/output
    schema: Dict[str, Any]
    
    # Required permissions
    permissions: List[Permission]
```

### SignedToolDefinition

```python
@dataclass
class SignedToolDefinition(ToolDefinition):
    # Base64-encoded signature of the definition
    signature: str
    
    # Signature algorithm used
    signature_algorithm: str
    
    # Optional OAuth token
    oauth: Optional[Dict[str, str]] = None
```

### Permission

```python
@dataclass
class Permission:
    # Permission name
    name: str
    
    # Human-readable description
    description: str
    
    # OAuth scope equivalent
    scope: str
    
    # Whether the permission is required
    required: bool
```

## Usage Examples

### Basic Tool Discovery and Invocation

```python
from etdi import ETDIClient

async def main():
    # Initialize client
    client = ETDIClient(
        security_level="enhanced",
        oauth_config={
            "provider": "auth0",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "domain": "your-auth0-domain"
        }
    )
    
    # Discover tools
    tools = await client.discover_tools()
    
    # Filter verified tools
    verified_tools = []
    for tool in tools:
        is_verified = await client.verify_tool(tool)
        if is_verified:
            verified_tools.append(tool)
    
    # Display available tools
    print(f"Discovered {len(verified_tools)} tools:")
    
    for tool in verified_tools:
        print(f"- {tool.name} (v{tool.version}) by {tool.provider['name']}")
        
        # Check if tool is approved
        is_approved = await client.is_tool_approved(tool.id)
        
        if is_approved:
            print("  ✓ Tool approved")
        else:
            print("  ⚠ Tool not approved - approval required")
            
            # Request approval (in a real app, you would show UI to the user)
            await client.approve_tool(tool)
            print("  ✓ Tool approved")
    
    # Invoke a tool
    if verified_tools:
        tool = verified_tools[0]
        print(f"Invoking {tool.name}...")
        
        result = await client.invoke_tool(tool.id, {
            # Tool parameters
        })
        
        print("Result:", result)

# Run the async function
import asyncio
asyncio.run(main())
```

### Creating and Registering a Tool

```python
from etdi import ToolProvider, ToolDefinition, Permission

async def register_tool():
    # Initialize provider
    provider = ToolProvider(
        name="MyToolProvider",
        version="1.0.0",
        public_key="your-public-key",
        private_key="your-private-key"
    )
    
    # Define tool
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
    
    # Register tool
    signed_tool = await provider.register_tool(tool_definition)
    
    print(f"Tool registered successfully: {signed_tool.name} (v{signed_tool.version})")
    print(f"Signature: {signed_tool.signature[:20]}...")

# Run the async function
import asyncio
asyncio.run(register_tool())
```

### Advanced OAuth Integration

```python
from etdi import ETDIClient, OAuthManager

async def setup_with_oauth():
    # Initialize OAuth manager
    oauth_manager = OAuthManager(
        provider="auth0",
        client_id="your-client-id",
        client_secret="your-client-secret",
        domain="your-auth0-domain",
        audience="your-audience",
        scopes=["openid", "profile", "email"]
    )
    
    # Initialize manager
    await oauth_manager.initialize()
    
    # Get token
    token = await oauth_manager.get_token()
    
    # Initialize ETDI client with OAuth manager
    client = ETDIClient(
        security_level="enhanced",
        oauth_manager=oauth_manager
    )
    
    # Use client
    tools = await client.discover_tools()
    
    # Check permissions
    has_permissions = await client.check_permission("my-tool", "read:data")
    
    if has_permissions:
        # Invoke tool
        result = await client.invoke_tool("my-tool", {
            # Tool parameters
        })
        
        print("Result:", result)

# Run the async function
import asyncio
asyncio.run(setup_with_oauth())
```

## Error Handling

```python
from etdi import ETDIClient, ETDIError

async def handle_errors():
    client = ETDIClient(
        security_level="enhanced",
        oauth_config={
            "provider": "auth0",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "domain": "your-auth0-domain"
        }
    )
    
    try:
        await client.verify_tool(tool)
    except ETDIError as error:
        match error.code:
            case "SIGNATURE_INVALID":
                print("Tool signature is invalid")
            case "PROVIDER_NOT_FOUND":
                print("Provider not found")
            case "VERSION_MISMATCH":
                print("Version mismatch detected")
            case _:
                print(f"Unknown ETDI error: {error.message}")
    except Exception as error:
        print(f"Unexpected error: {error}")

# Run the async function
import asyncio
asyncio.run(handle_errors())
```

## Events

```python
from etdi import ETDIClient

def setup_events():
    client = ETDIClient(
        security_level="enhanced",
        oauth_config={
            "provider": "auth0",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "domain": "your-auth0-domain"
        }
    )
    
    # Tool events
    @client.on("tool_verified")
    def on_tool_verified(tool):
        print(f"Tool {tool.name} verified successfully")
    
    @client.on("tool_approved")
    def on_tool_approved(tool):
        print(f"Tool {tool.name} approved by user")
    
    @client.on("version_changed")
    def on_version_changed(tool):
        print(f"Tool {tool.name} version changed from {tool.old_version} to {tool.new_version}")
    
    @client.on("permission_changed")
    def on_permission_changed(tool):
        print(f"Tool {tool.name} permissions changed")
    
    # OAuth events
    @client.on("token_refreshed")
    def on_token_refreshed():
        print("OAuth token refreshed")
    
    @client.on("token_expired")
    def on_token_expired():
        print("OAuth token expired")

setup_events()
```

## Advanced Configuration

### Custom Provider

```python
from etdi import CustomOAuthProvider, OAuthManager

async def setup_custom_provider():
    # Implement custom provider
    class MyCustomProvider(CustomOAuthProvider):
        async def get_token(self):
            # Custom token acquisition logic
            pass
        
        async def validate_token(self, token):
            # Custom token validation logic
            pass
        
        async def refresh_token(self, token):
            # Custom token refresh logic
            pass
    
    # Register custom provider
    provider = MyCustomProvider(
        # Provider-specific configuration
    )
    
    # Use custom provider
    oauth_manager = OAuthManager(
        provider=provider
    )
    
    # Continue with normal flow
    
# Run the async function
import asyncio
asyncio.run(setup_custom_provider())
```

### Custom Storage

```python
from etdi import CustomStorageProvider, ETDIClient

async def setup_custom_storage():
    # Implement custom storage
    class MyStorageProvider(CustomStorageProvider):
        async def store_approval(self, record):
            # Custom storage logic
            pass
        
        async def get_approval(self, tool_id):
            # Custom retrieval logic
            pass
        
        async def remove_approval(self, tool_id):
            # Custom removal logic
            pass
    
    # Use custom storage
    storage = MyStorageProvider()
    
    client = ETDIClient(
        security_level="enhanced",
        storage_config={
            "provider": storage
        },
        oauth_config={
            "provider": "auth0",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "domain": "your-auth0-domain"
        }
    )
    
    # Continue with normal flow

# Run the async function
import asyncio
asyncio.run(setup_custom_storage())
```

## Integration with Model Context Protocol

The ETDI Python SDK is designed to work seamlessly with the [Model Context Protocol (MCP) Python SDK](https://github.com/modelcontextprotocol/python-sdk).

```python
from etdi import ETDIClient
from mcp import ClientSession
from mcp.client.stdio import stdio_client

async def integrate_with_mcp():
    # Setup ETDI client
    etdi_client = ETDIClient(
        security_level="enhanced",
        oauth_config={
            "provider": "auth0",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "domain": "your-auth0-domain"
        }
    )
    
    # Discover and verify tools
    tools = await etdi_client.discover_tools()
    verified_tools = []
    
    for tool in tools:
        if await etdi_client.verify_tool(tool):
            if not await etdi_client.is_tool_approved(tool.id):
                await etdi_client.approve_tool(tool)
            verified_tools.append(tool)
    
    # Connect to MCP server
    async with stdio_client(command="python3", args=["mcp_server.py"]) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize MCP session
            await session.initialize()
            
            # Register ETDI tools with MCP
            for tool in verified_tools:
                # Convert ETDI tool to MCP tool format
                mcp_tool = {
                    "name": tool.id,
                    "description": tool.description,
                    "parameters": tool.schema
                }
                
                # Call the tool through MCP
                result = await session.call_tool(
                    mcp_tool["name"], 
                    {"param1": "value1"}
                )
                
                print(f"Tool result: {result}")

# Run the async function
import asyncio
asyncio.run(integrate_with_mcp())
```

## Next Steps

- Check the [API Reference](api-reference.md) for a complete list of classes, methods, and interfaces
- Look at the [Examples](examples.md) for more detailed code samples
- Review the [Best Practices](../implementation/best-practices.md) for implementation recommendations 