# Future Considerations
This document contains a list of future additions, improvements or other considerations outside the scope of the initial version of ETDI.

## MCP Tool Backend/API Contract Verification
The Tool Definition does not include information about the backend functionality of an MCP tool, or its API contracts. Theoretically, an actor could perform a similar action to the Rug Pull Attack by changing the functionality of the tool's inner workings or APIs, without modifying the Tool Definition. This would bypass the Tool Definition verification. 

### Current ETDI Scope and Security
The description and parameters of an MCP tool are a crucial element of its operation/functionality. Additionally, these elements are published and externally verifiable via the Tool Definition. As such, ETDI is scoped to validate and secure these important characteristics, which are necessarily available for MCP operation. 

### Challenges For Implementation
In order to secure this additional component, a backend API call chain, or a fingerprint of the backend code, would need to be included in the Tool Definition. It could be computationally expensive to create this, and still could require trust in the developer of the tool to properly fingerprint backend functionality. As such, this is currently out of scope.
