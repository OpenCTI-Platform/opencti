import nconf from 'nconf';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp';
import { basePath, logApp, PLATFORM_VERSION } from '../config/conf';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import createSchema from '../graphql/schema';
import { registerAllTools } from '../mcp/mcpTools';

const MCP_ENABLED = nconf.get('app:mcp:enabled') ?? true;

const initMcpApi = (app) => {
  if (!MCP_ENABLED) {
    logApp.info('[MCP] MCP server is disabled');
    return;
  }

  const schema = createSchema();

  app.post(`${basePath}/mcp`, async (req, res) => {
    try {
      const context = await createAuthenticatedContext(req, res, 'mcp');
      if (!context.user) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        res.status(401).json({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Authentication required' },
          id: req.body?.id ?? null,
        });
        return;
      }

      const server = new McpServer({
        name: 'opencti',
        version: PLATFORM_VERSION,
      });

      registerAllTools(server, schema, context);

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
      });

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      logApp.error('[MCP] Error handling MCP request', { cause: e });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: req.body?.id ?? null,
        });
      }
    }
  });

  app.get(`${basePath}/mcp`, (req, res) => {
    res.status(405).json({ error: 'Method not allowed. Use POST for MCP requests.' });
  });

  app.delete(`${basePath}/mcp`, (req, res) => {
    res.status(405).json({ error: 'Session termination not supported in stateless mode.' });
  });

  logApp.info(`[MCP] MCP server initialized on POST ${basePath}/mcp`);
};

export default initMcpApi;
