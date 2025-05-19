# Future Considerations
This document contains a list of future additions, improvements or other considerations outside the scope of the initial version of ETDI.

## Tool Backend API Verification
The Tool Definition does not include information about the backend functionality of an MCP tool. Theoretically, an actor could perform a similar action to the Rug Pull Attack by changing the functionality of the tool, without modifying the Tool Definition. This would bypass the Tool Definition verification. 

### Existing Scope and Security
The description and parameters of an MCP tool are a crucial element in its operation/functionality. Additionally, these elements are published and externally verifiable. As such, ETDI is scoped to validate and secure these important characteristics, which are necessarily available for MCP operation.

### Challenges For Implementation
In order to secure this additional component, a backend API call chain, or a fingerprint of the backend code, would need to be included in the tool definition. It could be computationally expensive to create this, and still could require trust in the developer of the tool to properly fingerprint backend functionality.
