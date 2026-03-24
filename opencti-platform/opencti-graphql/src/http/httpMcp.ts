import type Express from 'express';
import type { GraphQLSchema } from 'graphql';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp';
import { basePath, logApp, PLATFORM_VERSION } from '../config/conf';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { registerAllTools } from '../mcp/mcpTools';
import type { BasicStoreSettings } from '../types/settings';

let currentContext: Record<string, any> | null = null;

const initMcpApi = (app: Express.Application, schema: GraphQLSchema): void => {
  const server = new McpServer({
    name: 'opencti',
    version: PLATFORM_VERSION,
  });

  registerAllTools(server, schema, () => currentContext!);

  app.post(`${basePath}/mcp`, async (req: Express.Request, res: Express.Response) => {
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

      const settings = await getEntityFromCache<BasicStoreSettings>(context, context.user, ENTITY_TYPE_SETTINGS);
      if (!settings.platform_mcp_enabled) {
        res.status(404).json({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'MCP server is disabled' },
          id: req.body?.id ?? null,
        });
        return;
      }

      currentContext = context;

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);

      currentContext = null;
    } catch (e) {
      currentContext = null;
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

  app.get(`${basePath}/mcp`, (_req: Express.Request, res: Express.Response) => {
    res.status(405).json({ error: 'Method not allowed. Use POST for MCP requests.' });
  });

  app.delete(`${basePath}/mcp`, (_req: Express.Request, res: Express.Response) => {
    res.status(405).json({ error: 'Session termination not supported in stateless mode.' });
  });

  logApp.info(`[MCP] MCP server initialized on POST ${basePath}/mcp`);
};

export default initMcpApi;
