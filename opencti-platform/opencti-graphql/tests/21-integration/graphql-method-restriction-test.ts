import { describe, expect, it } from 'vitest';
import { API_URI } from '../utils/testQuery';

describe('GraphQL HTTP method restriction integration', () => {
  it('should reject standard GET GraphQL requests with 405 and Allow: POST', async () => {
    const response = await fetch(`${API_URI}/graphql?${new URLSearchParams({ query: '{ __typename }' })}`);

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')?.split(',').map((m) => m.trim())).toContain('POST');
    expect((await response.json() as { name?: string }).name).toBe('MethodNotAllowedError');
  });
});
