"""hermes-mcp-login — browser-triggered OAuth login for a Hermes agent's MCP servers.

A small co-located web service that lets a user start the OAuth browser login
for an OAuth-protected MCP server (e.g. ``imcontact``) without SSH, paste, or
CLs. It does **no** OAuth of its own and rebuilds **no** token format: it drives
Hermes' own OAuth building blocks in-process and writes through Hermes'
``HermesTokenStorage``.

See ``README.md`` for the deployment model and design rationale.
"""

__version__ = "0.1.0"
