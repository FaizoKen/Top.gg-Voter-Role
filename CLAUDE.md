# VoterRole

A Rust project for Discord bot vote role management.

## API Reference Documentation

When working on this project, always refer to the following API documentation:

### RoleLogic API
- **Role Link API**: https://docs-rolelogic.faizo.net/reference/role-link-api

### Top.gg API v1 (currently used)
- **Introduction**: https://docs.top.gg/docs/API/v1/@introduction
- **Integrations**: https://docs.top.gg/docs/API/v1/integrations
- **Projects**: https://docs.top.gg/docs/API/v1/projects
- **Webhooks**: https://docs.top.gg/docs/API/v1/webhooks

Use `WebFetch` to fetch these docs when you need to understand endpoint schemas, request/response formats, or authentication details.

## Development Priorities

- **Performance**: Optimize for speed and low resource usage (CPU, memory). Prefer efficient algorithms, minimize allocations, and avoid unnecessary overhead.
- **Low-cost hosting**: This project runs on budget/low-spec infrastructure. Keep the binary small, dependencies minimal, and runtime footprint light. Avoid bloated crates or features that increase resource consumption without clear benefit.
