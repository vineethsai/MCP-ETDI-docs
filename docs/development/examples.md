# ETDI Examples

This document provides practical examples of using ETDI in various scenarios.

## Basic Examples

### Tool Discovery and Verification

```typescript
import { ETDIClient } from '@etdi/sdk';

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

// Discover and verify tools
async function discoverAndVerifyTools() {
  try {
    // Discover all available tools
    const tools = await client.discoverTools();
    
    console.log(`Discovered ${tools.length} tools:`);
    
    // Process each tool
    for (const tool of tools) {
      console.log(`- ${tool.name} (${tool.version}) by ${tool.provider.name}`);
      
      // Verify tool signature
      const isVerified = await client.verifyTool(tool);
      
      if (isVerified) {
        console.log(`  ✓ Signature verified`);
        
        // Check if tool is approved
        const isApproved = await client.isToolApproved(tool.id);
        
        if (isApproved) {
          console.log(`  ✓ Tool approved`);
        } else {
          console.log(`  ⚠ Tool not approved - approval required`);
          
          // Request approval (in a real app, you would show UI to the user)
          await client.approveTool(tool);
          console.log(`  ✓ Tool approved`);
        }
      } else {
        console.log(`  ✗ Signature verification failed - tool may be compromised`);
      }
    }
  } catch (error) {
    console.error('Error during tool discovery and verification:', error);
  }
}

discoverAndVerifyTools();
```

### Tool Invocation

```typescript
import { ETDIClient } from '@etdi/sdk';

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

// Invoke weather tool
async function getWeatherForecast(location: string) {
  try {
    // Check if tool is approved
    const isApproved = await client.isToolApproved('weather-tool');
    
    if (!isApproved) {
      console.log('Weather tool not approved. Requesting approval...');
      
      // Discover tool
      const tools = await client.discoverTools();
      const weatherTool = tools.find(tool => tool.id === 'weather-tool');
      
      if (!weatherTool) {
        throw new Error('Weather tool not found');
      }
      
      // Verify and approve tool
      const isVerified = await client.verifyTool(weatherTool);
      
      if (!isVerified) {
        throw new Error('Weather tool signature verification failed');
      }
      
      // Request approval (in a real app, you would show UI to the user)
      await client.approveTool(weatherTool);
      console.log('Weather tool approved');
    }
    
    // Check for version changes
    const versionChanged = await client.checkVersionChange('weather-tool');
    
    if (versionChanged) {
      console.log('Weather tool version has changed. Requesting re-approval...');
      
      // Request re-approval (in a real app, you would show UI to the user)
      await client.requestReapproval('weather-tool');
      console.log('Weather tool re-approved');
    }
    
    // Invoke tool
    console.log(`Getting weather forecast for ${location}...`);
    
    const result = await client.invokeTool('weather-tool', {
      location,
      units: 'metric'
    });
    
    console.log('Weather forecast:');
    console.log(`- Temperature: ${result.temperature}°C`);
    console.log(`- Conditions: ${result.conditions}`);
    console.log(`- Humidity: ${result.humidity}%`);
    
    return result;
  } catch (error) {
    console.error('Error getting weather forecast:', error);
    throw error;
  }
}

getWeatherForecast('New York');
```

## Advanced Examples

### Creating and Registering a Tool

```typescript
import { ToolProvider, ToolDefinition } from '@etdi/sdk';

// Initialize provider
const provider = new ToolProvider({
  name: 'WeatherServices',
  version: '1.0.0',
  publicKey: 'your-public-key',
  privateKey: 'your-private-key'
});

// Define and register weather tool
async function createWeatherTool() {
  try {
    // Define tool
    const weatherToolDefinition: ToolDefinition = {
      id: 'weather-tool',
      name: 'Weather Forecast',
      version: '1.0.0',
      description: 'Provides weather forecasts for locations worldwide',
      provider: {
        id: provider.id,
        name: provider.name
      },
      permissions: [
        {
          name: 'location',
          description: 'Access to your location',
          scope: 'read:location',
          required: true
        },
        {
          name: 'network',
          description: 'Internet access',
          scope: 'network:access',
          required: true
        }
      ],
      schema: {
        type: 'object',
        properties: {
          location: {
            type: 'string',
            description: 'Location name (city, address, etc.)'
          },
          units: {
            type: 'string',
            enum: ['metric', 'imperial'],
            default: 'metric',
            description: 'Temperature units'
          }
        },
        required: ['location'],
        additionalProperties: false
      }
    };
    
    // Register tool
    const signedTool = await provider.registerTool(weatherToolDefinition);
    
    console.log('Weather tool registered successfully:');
    console.log(`- ID: ${signedTool.id}`);
    console.log(`- Version: ${signedTool.version}`);
    console.log(`- Signature: ${signedTool.signature.substring(0, 20)}...`);
    
    return signedTool;
  } catch (error) {
    console.error('Error creating weather tool:', error);
    throw error;
  }
}

// Define and register translation tool
async function createTranslationTool() {
  try {
    // Define tool
    const translationToolDefinition: ToolDefinition = {
      id: 'translation-tool',
      name: 'Text Translator',
      version: '1.0.0',
      description: 'Translates text between languages',
      provider: {
        id: provider.id,
        name: provider.name
      },
      permissions: [
        {
          name: 'network',
          description: 'Internet access',
          scope: 'network:access',
          required: true
        }
      ],
      schema: {
        type: 'object',
        properties: {
          text: {
            type: 'string',
            description: 'Text to translate'
          },
          sourceLanguage: {
            type: 'string',
            description: 'Source language code (ISO 639-1)'
          },
          targetLanguage: {
            type: 'string',
            description: 'Target language code (ISO 639-1)'
          }
        },
        required: ['text', 'targetLanguage'],
        additionalProperties: false
      }
    };
    
    // Register tool
    const signedTool = await provider.registerTool(translationToolDefinition);
    
    console.log('Translation tool registered successfully:');
    console.log(`- ID: ${signedTool.id}`);
    console.log(`- Version: ${signedTool.version}`);
    console.log(`- Signature: ${signedTool.signature.substring(0, 20)}...`);
    
    return signedTool;
  } catch (error) {
    console.error('Error creating translation tool:', error);
    throw error;
  }
}

async function createAndRegisterTools() {
  await createWeatherTool();
  await createTranslationTool();
  
  // List all registered tools
  const tools = await provider.getTools();
  console.log(`\nTotal registered tools: ${tools.length}`);
}

createAndRegisterTools();
```

### OAuth Integration

```typescript
import { ETDIClient, OAuthManager } from '@etdi/sdk';

// Setup OAuth manager
const oauthManager = new OAuthManager({
  provider: 'auth0',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  domain: 'your-auth0-domain',
  audience: 'your-audience',
  scopes: ['openid', 'profile', 'email']
});

// Initialize client with OAuth manager
const client = new ETDIClient({
  securityLevel: 'enhanced',
  oauthManager
});

// Handle OAuth flow
async function setupOAuth() {
  try {
    // Initialize OAuth manager
    await oauthManager.initialize();
    
    // Get token
    const token = await oauthManager.getToken();
    console.log('OAuth token acquired');
    
    // Check scopes
    const hasScopes = await oauthManager.hasScopes(['read:location', 'network:access']);
    
    if (!hasScopes) {
      console.log('Requesting additional scopes...');
      
      // Request additional scopes
      const newToken = await oauthManager.requestScopes(['read:location', 'network:access']);
      console.log('New token with additional scopes acquired');
    }
    
    return token;
  } catch (error) {
    console.error('OAuth setup error:', error);
    throw error;
  }
}

// Use OAuth with tool invocation
async function invokeToolWithOAuth() {
  try {
    // Setup OAuth
    await setupOAuth();
    
    // Discover tools
    const tools = await client.discoverTools();
    console.log(`Discovered ${tools.length} tools`);
    
    // Find and invoke translation tool
    const translationTool = tools.find(tool => tool.id === 'translation-tool');
    
    if (!translationTool) {
      throw new Error('Translation tool not found');
    }
    
    // Verify and approve tool
    const isVerified = await client.verifyTool(translationTool);
    
    if (!isVerified) {
      throw new Error('Translation tool verification failed');
    }
    
    // Approve tool if needed
    if (!(await client.isToolApproved(translationTool.id))) {
      await client.approveTool(translationTool);
      console.log('Translation tool approved');
    }
    
    // Invoke tool
    const result = await client.invokeTool('translation-tool', {
      text: 'Hello, world!',
      targetLanguage: 'es'
    });
    
    console.log('Translation result:');
    console.log(`- Original: Hello, world!`);
    console.log(`- Translated: ${result.translatedText}`);
    
    return result;
  } catch (error) {
    console.error('Error invoking tool with OAuth:', error);
    throw error;
  }
}

invokeToolWithOAuth();
```

### Custom Provider Implementation

```typescript
import { CustomOAuthProvider, OAuthManager, ETDIClient } from '@etdi/sdk';

// Implement custom OAuth provider
class CustomProvider extends CustomOAuthProvider {
  constructor(config) {
    super(config);
    this.config = config;
  }
  
  async getToken() {
    console.log('Getting token from custom provider...');
    
    // Custom token acquisition logic
    // This is a simplified example - in a real implementation, 
    // you would make actual API calls to your authentication server
    
    return 'custom-token-123';
  }
  
  async validateToken(token) {
    console.log('Validating token with custom provider...');
    
    // Custom token validation logic
    return token === 'custom-token-123';
  }
  
  async refreshToken(token) {
    console.log('Refreshing token with custom provider...');
    
    // Custom token refresh logic
    return 'custom-token-refreshed-456';
  }
}

// Use custom provider
async function useCustomProvider() {
  try {
    // Create custom provider
    const customProvider = new CustomProvider({
      // Provider-specific configuration
      serverUrl: 'https://auth.example.com',
      apiKey: 'your-api-key'
    });
    
    // Create OAuth manager with custom provider
    const oauthManager = new OAuthManager({
      provider: customProvider
    });
    
    // Initialize OAuth manager
    await oauthManager.initialize();
    
    // Get token
    const token = await oauthManager.getToken();
    console.log('Custom token acquired:', token);
    
    // Create client with custom provider
    const client = new ETDIClient({
      securityLevel: 'enhanced',
      oauthManager
    });
    
    // Use client normally
    const tools = await client.discoverTools();
    console.log(`Discovered ${tools.length} tools`);
    
    return token;
  } catch (error) {
    console.error('Error using custom provider:', error);
    throw error;
  }
}

useCustomProvider();
```

### Error Handling

```typescript
import { ETDIClient, ETDIError, SignatureError, VersionError, PermissionError } from '@etdi/sdk';

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

// Comprehensive error handling example
async function handleErrors() {
  try {
    // Discover tools
    const tools = await client.discoverTools();
    const toolId = 'data-analysis-tool';
    
    // Find specific tool
    const tool = tools.find(t => t.id === toolId);
    
    if (!tool) {
      console.error(`Tool not found: ${toolId}`);
      return;
    }
    
    try {
      // Verify tool
      const isVerified = await client.verifyTool(tool);
      
      if (!isVerified) {
        throw new Error('Tool verification failed');
      }
      
      console.log(`Tool verified: ${tool.name}`);
    } catch (error) {
      if (error instanceof SignatureError) {
        console.error(`Signature verification failed for tool: ${tool.name}`);
        console.error(`Error code: ${error.code}`);
        
        // Handle specific signature error
        // Example: Report potential security issue
        reportSecurityIssue({
          type: 'signature_invalid',
          toolId: tool.id,
          providerId: tool.provider.id
        });
        
        return;
      } else {
        // Re-throw other errors
        throw error;
      }
    }
    
    try {
      // Check version changes
      const versionChanged = await client.checkVersionChange(toolId);
      
      if (versionChanged) {
        console.log('Tool version has changed. Requesting re-approval...');
        
        // Request re-approval
        await client.requestReapproval(toolId);
      }
    } catch (error) {
      if (error instanceof VersionError) {
        console.error(`Version error for tool: ${tool.name}`);
        console.error(`Old version: ${error.oldVersion}, New version: ${error.newVersion}`);
        
        // Check if major version change
        const oldMajor = parseInt(error.oldVersion.split('.')[0]);
        const newMajor = parseInt(error.newVersion.split('.')[0]);
        
        if (newMajor > oldMajor) {
          console.log('Major version upgrade detected - requires manual approval');
          // Show UI for manual approval
        } else {
          console.log('Minor version change - can be automatically approved');
          // Auto-approve
          await client.approveTool(tool);
        }
        
        return;
      } else {
        // Re-throw other errors
        throw error;
      }
    }
    
    try {
      // Check permissions
      const canReadData = await client.checkPermission(toolId, 'read:data');
      const canWriteData = await client.checkPermission(toolId, 'write:data');
      
      if (!canReadData || !canWriteData) {
        console.error('Insufficient permissions');
        return;
      }
      
      // Invoke tool
      const result = await client.invokeTool(toolId, {
        // Tool parameters
        operation: 'analyze',
        data: [1, 2, 3, 4, 5]
      });
      
      console.log('Tool invocation successful');
      console.log('Result:', result);
    } catch (error) {
      if (error instanceof PermissionError) {
        console.error(`Permission error for tool: ${tool.name}`);
        console.error('Required permissions:', error.requiredPermissions);
        console.error('Approved permissions:', error.approvedPermissions);
        
        // Show UI for permission approval
        console.log('Additional permissions required:');
        
        for (const reqPerm of error.requiredPermissions) {
          const approved = error.approvedPermissions.some(p => p.name === reqPerm.name);
          
          if (!approved) {
            console.log(`- ${reqPerm.name}: ${reqPerm.description}`);
          }
        }
        
        return;
      } else if (error instanceof ETDIError) {
        console.error(`ETDI error: ${error.message}`);
        console.error(`Error code: ${error.code}`);
        return;
      } else {
        // Re-throw other errors
        throw error;
      }
    }
  } catch (error) {
    console.error('Unexpected error:', error);
  }
}

// Utility function for reporting security issues (example)
function reportSecurityIssue(issue) {
  console.log('Reporting security issue:', issue);
  // In a real application, you would send this to your security monitoring system
}

handleErrors();
```

## React Integration Examples

### Tool Discovery Component

```tsx
import React, { useState, useEffect } from 'react';
import { ETDIClient, ToolDefinition } from '@etdi/sdk';

// Initialize client outside of component
const client = new ETDIClient({
  securityLevel: 'enhanced',
  oauthConfig: {
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain'
  }
});

// Tool discovery component
const ToolDiscovery: React.FC = () => {
  const [tools, setTools] = useState<ToolDefinition[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    // Discover tools on component mount
    const discoverTools = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Discover tools
        const discoveredTools = await client.discoverTools();
        
        // Filter verified tools
        const verifiedTools = await Promise.all(
          discoveredTools.map(async (tool) => {
            const isVerified = await client.verifyTool(tool);
            const isApproved = await client.isToolApproved(tool.id);
            
            return {
              ...tool,
              isVerified,
              isApproved
            };
          })
        );
        
        setTools(verifiedTools);
      } catch (err) {
        setError(err.message || 'Failed to discover tools');
      } finally {
        setLoading(false);
      }
    };
    
    discoverTools();
  }, []);
  
  // Handle tool approval
  const handleApprove = async (tool: ToolDefinition) => {
    try {
      await client.approveTool(tool);
      
      // Update tool status in state
      setTools(tools.map(t => 
        t.id === tool.id ? { ...t, isApproved: true } : t
      ));
    } catch (err) {
      setError(`Failed to approve tool: ${err.message}`);
    }
  };
  
  if (loading) {
    return <div>Loading available tools...</div>;
  }
  
  if (error) {
    return <div className="error">Error: {error}</div>;
  }
  
  return (
    <div className="tool-discovery">
      <h2>Available Tools</h2>
      
      {tools.length === 0 ? (
        <p>No tools discovered</p>
      ) : (
        <ul className="tool-list">
          {tools.map((tool) => (
            <li key={tool.id} className="tool-item">
              <div className="tool-header">
                <h3>{tool.name} <span className="version">v{tool.version}</span></h3>
                {tool.isVerified ? (
                  <span className="verified-badge">✓ Verified</span>
                ) : (
                  <span className="unverified-badge">⚠ Unverified</span>
                )}
              </div>
              
              <p className="tool-description">{tool.description}</p>
              <p className="tool-provider">Provider: {tool.provider.name}</p>
              
              <div className="tool-permissions">
                <h4>Permissions:</h4>
                <ul>
                  {tool.permissions.map((permission) => (
                    <li key={permission.name}>
                      {permission.name}: {permission.description}
                      {permission.required && <span className="required">*</span>}
                    </li>
                  ))}
                </ul>
              </div>
              
              {tool.isVerified && !tool.isApproved && (
                <button 
                  className="approve-button"
                  onClick={() => handleApprove(tool)}
                >
                  Approve Tool
                </button>
              )}
              
              {tool.isApproved && (
                <span className="approved-badge">✓ Approved</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default ToolDiscovery;
```

### Tool Invocation Component

```tsx
import React, { useState } from 'react';
import { ETDIClient } from '@etdi/sdk';

// Initialize client outside of component
const client = new ETDIClient({
  securityLevel: 'enhanced',
  oauthConfig: {
    provider: 'auth0',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    domain: 'your-auth0-domain'
  }
});

// Props for the component
interface ToolInvocationProps {
  toolId: string;
  toolName: string;
  toolDescription: string;
}

// Tool invocation component
const ToolInvocation: React.FC<ToolInvocationProps> = ({ toolId, toolName, toolDescription }) => {
  const [inputText, setInputText] = useState<string>('');
  const [targetLanguage, setTargetLanguage] = useState<string>('es');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!inputText) {
      setError('Please enter text to translate');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      // Check if tool is approved
      const isApproved = await client.isToolApproved(toolId);
      
      if (!isApproved) {
        setError(`Tool "${toolName}" is not approved. Please approve it first.`);
        return;
      }
      
      // Invoke tool
      const translationResult = await client.invokeTool(toolId, {
        text: inputText,
        targetLanguage
      });
      
      setResult(translationResult);
    } catch (err) {
      setError(err.message || 'Translation failed');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="tool-invocation">
      <h2>{toolName}</h2>
      <p>{toolDescription}</p>
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="inputText">Text to translate:</label>
          <textarea
            id="inputText"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Enter text to translate"
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="targetLanguage">Target language:</label>
          <select
            id="targetLanguage"
            value={targetLanguage}
            onChange={(e) => setTargetLanguage(e.target.value)}
          >
            <option value="es">Spanish</option>
            <option value="fr">French</option>
            <option value="de">German</option>
            <option value="it">Italian</option>
            <option value="ja">Japanese</option>
            <option value="zh">Chinese</option>
          </select>
        </div>
        
        <button 
          type="submit" 
          className="translate-button"
          disabled={loading}
        >
          {loading ? 'Translating...' : 'Translate'}
        </button>
      </form>
      
      {error && (
        <div className="error-message">
          Error: {error}
        </div>
      )}
      
      {result && (
        <div className="result-container">
          <h3>Translation Result</h3>
          <div className="result-original">
            <strong>Original:</strong> {inputText}
          </div>
          <div className="result-translation">
            <strong>Translation:</strong> {result.translatedText}
          </div>
          <div className="result-metadata">
            <strong>Detected language:</strong> {result.detectedLanguage || 'N/A'}
          </div>
        </div>
      )}
    </div>
  );
};

export default ToolInvocation;
```

## Node.js Server Examples

### Express Server with ETDI

```typescript
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { ETDIClient, ToolProvider } from '@etdi/sdk';

// Initialize Express app
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Initialize ETDI client
const client = new ETDIClient({
  securityLevel: 'enhanced',
  oauthConfig: {
    provider: 'auth0',
    clientId: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    domain: process.env.AUTH0_DOMAIN
  }
});

// Initialize tool provider
const provider = new ToolProvider({
  name: 'ServerTools',
  version: '1.0.0',
  publicKey: process.env.PROVIDER_PUBLIC_KEY,
  privateKey: process.env.PROVIDER_PRIVATE_KEY
});

// API routes

// Get available tools
app.get('/api/tools', async (req, res) => {
  try {
    const tools = await client.discoverTools();
    
    // Filter verified tools
    const verifiedTools = [];
    
    for (const tool of tools) {
      const isVerified = await client.verifyTool(tool);
      
      if (isVerified) {
        verifiedTools.push({
          id: tool.id,
          name: tool.name,
          version: tool.version,
          description: tool.description,
          provider: tool.provider.name,
          permissions: tool.permissions.map(p => ({
            name: p.name,
            description: p.description,
            required: p.required
          }))
        });
      }
    }
    
    res.json(verifiedTools);
  } catch (error) {
    console.error('Error fetching tools:', error);
    res.status(500).json({ error: 'Failed to fetch tools' });
  }
});

// Approve a tool
app.post('/api/tools/:toolId/approve', async (req, res) => {
  try {
    const { toolId } = req.params;
    
    // Find tool
    const tools = await client.discoverTools();
    const tool = tools.find(t => t.id === toolId);
    
    if (!tool) {
      return res.status(404).json({ error: 'Tool not found' });
    }
    
    // Verify tool
    const isVerified = await client.verifyTool(tool);
    
    if (!isVerified) {
      return res.status(400).json({ error: 'Tool verification failed' });
    }
    
    // Approve tool
    await client.approveTool(tool);
    
    res.json({ success: true, message: `Tool "${tool.name}" approved successfully` });
  } catch (error) {
    console.error('Error approving tool:', error);
    res.status(500).json({ error: 'Failed to approve tool' });
  }
});

// Invoke a tool
app.post('/api/tools/:toolId/invoke', async (req, res) => {
  try {
    const { toolId } = req.params;
    const params = req.body;
    
    // Check if tool is approved
    const isApproved = await client.isToolApproved(toolId);
    
    if (!isApproved) {
      return res.status(403).json({ error: 'Tool not approved' });
    }
    
    // Check version changes
    const versionChanged = await client.checkVersionChange(toolId);
    
    if (versionChanged) {
      return res.status(409).json({ 
        error: 'Tool version has changed', 
        requiresReapproval: true 
      });
    }
    
    // Invoke tool
    const result = await client.invokeTool(toolId, params);
    
    res.json(result);
  } catch (error) {
    console.error('Error invoking tool:', error);
    res.status(500).json({ error: 'Failed to invoke tool' });
  }
});

// Register a new tool
app.post('/api/provider/tools', async (req, res) => {
  try {
    const toolDefinition = req.body;
    
    // Register tool
    const signedTool = await provider.registerTool(toolDefinition);
    
    res.json({
      success: true,
      tool: {
        id: signedTool.id,
        name: signedTool.name,
        version: signedTool.version,
        signature: signedTool.signature
      }
    });
  } catch (error) {
    console.error('Error registering tool:', error);
    res.status(500).json({ error: 'Failed to register tool' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
``` 