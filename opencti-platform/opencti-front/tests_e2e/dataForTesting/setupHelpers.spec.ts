import { createServer } from 'node:http';
import { once } from 'node:events';
import { APIRequestContext } from '@playwright/test';
import { expect, test as base } from '../fixtures/baseFixtures';
import { addOrganizations, restrictOrganizationVisibility } from './organization.data';
import { authenticateAdminApi, waitForUserCapabilities } from './session.data';
import { executeGraphql } from './query-utils';

interface Reply {
  body: unknown;
  status?: number;
  headers?: Record<string, string>;
}

interface TestApi {
  request: APIRequestContext;
  respond: (handler: (query: string, authenticated: boolean) => Reply) => void;
}

const test = base.extend<{ api: TestApi }>({
  api: async ({ playwright }, use) => {
    let handler: (query: string, authenticated: boolean) => Reply = () => ({ status: 500, body: {} });
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        const { query } = JSON.parse(Buffer.concat(chunks).toString());
        const reply = handler(query, request.headers.cookie === 'fixture-session=active');
        response.writeHead(reply.status ?? 200, { 'Content-Type': 'application/json', ...reply.headers });
        response.end(JSON.stringify(reply.body));
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Fixture API server did not bind a TCP port');
    }
    const request = await playwright.request.newContext({
      baseURL: `http://127.0.0.1:${address.port}`,
      storageState: { cookies: [], origins: [] },
    });
    try {
      await use({
        request,
        respond: (nextHandler) => {
          handler = nextHandler;
        },
      });
    } finally {
      await request.dispose();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  },
});

const authRequired = {
  data: { organizations: null },
  errors: [{ message: 'You must be logged in to do this.', extensions: { code: 'AUTH_REQUIRED' } }],
};
const organizations = {
  edges: ['OrgA', 'OrgC'].map((name) => ({ node: { id: name, name } })),
};
const me = (email: string, capabilities: string[]) => ({
  user_email: email,
  capabilities: capabilities.map((name) => ({ name })),
});

test.describe('Workflow setup API helpers', { tag: ['@ce', '@workflow', '@group1'] }, () => {
  test('reports the organizations authentication error instead of a null edges error', async ({ api }) => {
    api.respond(() => ({ body: authRequired }));
    await expect(restrictOrganizationVisibility(api.request, 'OrgA', ['OrgA', 'OrgC']))
      .rejects.toThrow('Get fixture organizations failed: AUTH_REQUIRED: You must be logged in to do this.');
  });

  test('reports failed organization creation', async ({ api }) => {
    api.respond((query) => ({
      body: query.includes('organizationAdd')
        ? { errors: [{ message: 'Creation denied', extensions: { code: 'FORBIDDEN' } }] }
        : { data: { organizations: { edges: [] } } },
    }));
    await expect(addOrganizations(api.request, [{ name: 'OrgA' }]))
      .rejects.toThrow('Create organization OrgA failed: FORBIDDEN: Creation denied');
  });

  test('reports a null organizations result even without GraphQL errors', async ({ api }) => {
    api.respond(() => ({ body: { data: { organizations: null } } }));
    await expect(addOrganizations(api.request, [])).rejects.toThrow('organizations is null');
  });

  test('reports failed organization access grants', async ({ api }) => {
    api.respond((query) => {
      if (query.includes('stixDomainObjectEdit')) {
        return { body: { errors: [{ message: 'Access grant denied', extensions: { code: 'FORBIDDEN' } }] } };
      }
      return { body: { data: query.includes('organizations') ? { organizations } : { me: { id: 'admin' } } } };
    });
    await expect(restrictOrganizationVisibility(api.request, 'OrgA', ['OrgA', 'OrgC']))
      .rejects.toThrow('restrictOrganizationVisibility failed: FORBIDDEN: Access grant denied');
  });

  test('reports missing organizations before trying to write grants', async ({ api }) => {
    api.respond(() => ({ body: { data: { organizations } } }));
    await expect(restrictOrganizationVisibility(api.request, 'OrgA', ['OrgB']))
      .rejects.toThrow('organization "OrgB" was not found');
  });

  test('requires the requested organization access grants to be returned', async ({ api }) => {
    api.respond((query) => {
      if (query.includes('stixDomainObjectEdit')) {
        return { body: { data: { stixDomainObjectEdit: {
          editAuthorizedMembers: { authorized_members: [{ member_id: 'admin', access_right: 'admin' }] },
        } } } };
      }
      return { body: { data: query.includes('organizations') ? { organizations } : { me: { id: 'admin' } } } };
    });
    await expect(restrictOrganizationVisibility(api.request, 'OrgA', ['OrgA', 'OrgC']))
      .rejects.toThrow('Expected OrgA\'s organization access grants to be saved');
  });

  test('authenticates the independent API cookie jar before fixture access', async ({ api }) => {
    let authenticatedReads = 0;
    api.respond((query, authenticated) => {
      if (query.includes('FixtureAdminLogin')) {
        return { body: { data: { token: true } }, headers: { 'Set-Cookie': 'fixture-session=active; Path=/' } };
      }
      if (!authenticated) {
        return { body: authRequired };
      }
      authenticatedReads += 1;
      return { body: { data: query.includes('organizations')
        ? { organizations }
        : { me: me('admin@opencti.io', ['BYPASS']) } } };
    });
    await expect(addOrganizations(api.request, [])).rejects.toThrow('AUTH_REQUIRED');
    await authenticateAdminApi(api.request);
    await addOrganizations(api.request, []);
    expect(authenticatedReads).toBe(2);
  });

  test('rejects failed login rather than trusting an existing admin identity', async ({ api }) => {
    let identityReads = 0;
    api.respond((query) => {
      if (query.includes('FixtureAdminLogin')) {
        return { body: { errors: [{ message: 'Authentication failed', extensions: { code: 'AUTH_FAILURE' } }] } };
      }
      identityReads += 1;
      return { body: { data: { me: me('admin@opencti.io', ['BYPASS']) } } };
    });
    await expect(authenticateAdminApi(api.request)).rejects.toThrow('Authenticate fixture admin failed: AUTH_FAILURE');
    expect(identityReads).toBe(0);
  });

  test('rejects an authenticated admin without effective BYPASS', async ({ api }) => {
    api.respond((query) => ({
      body: { data: query.includes('FixtureAdminLogin')
        ? { token: true }
        : { me: me('admin@opencti.io', ['KNOWLEDGE']) } },
    }));
    await expect(authenticateAdminApi(api.request)).rejects.toThrow('Fixture admin must have BYPASS');
  });

  test('waits for actual effective capabilities rather than successful requests', async ({ api }) => {
    let reads = 0;
    api.respond(() => {
      reads += 1;
      return { body: { data: { me: me('managerorgc@filigran.test', reads < 3
        ? ['KNOWLEDGE']
        : ['KNOWLEDGE', 'SETTINGS_SETCUSTOMIZATION']) } } };
    });
    await waitForUserCapabilities(api.request, 'managerorgc@filigran.test', ['SETTINGS_SETCUSTOMIZATION'], 2000);
    expect(reads).toBe(3);
  });

  test('fails readiness when permissions stay stale', async ({ api }) => {
    api.respond(() => ({ body: { data: { me: me('managerorgc@filigran.test', ['KNOWLEDGE']) } } }));
    await expect(waitForUserCapabilities(api.request, 'managerorgc@filigran.test', ['SETTINGS_SETCUSTOMIZATION'], 100))
      .rejects.toThrow('effective permissions to include SETTINGS_SETCUSTOMIZATION');
  });

  test('surfaces authentication errors while checking capability readiness', async ({ api }) => {
    api.respond(() => ({ body: authRequired }));
    await expect(waitForUserCapabilities(api.request, 'managerorgc@filigran.test', ['SETTINGS_SETCUSTOMIZATION'], 100))
      .rejects.toThrow('Read effective user permissions failed: AUTH_REQUIRED');
  });

  test('does not accept the required capabilities from the wrong identity', async ({ api }) => {
    api.respond(() => ({ body: { data: { me: me('admin@opencti.io', ['SETTINGS_SETCUSTOMIZATION']) } } }));
    await expect(waitForUserCapabilities(api.request, 'managerorgc@filigran.test', ['SETTINGS_SETCUSTOMIZATION'], 100))
      .rejects.toThrow('managerorgc@filigran.test');
  });

  test('reports HTTP failures and missing GraphQL data', async ({ api }) => {
    api.respond(() => ({ status: 503, body: {} }));
    await expect(executeGraphql(api.request, 'Read fixture', 'query { me { id } }'))
      .rejects.toThrow('Read fixture failed: HTTP 503');
    api.respond(() => ({ body: { data: null } }));
    await expect(executeGraphql(api.request, 'Read fixture', 'query { me { id } }'))
      .rejects.toThrow('Read fixture failed: response has no data');
  });
});
