import { describe, expect, it } from 'vitest';
import axios from 'axios';
import { API_URI } from '../utils/testQuery';

describe('GraphQL HTTP method restriction integration', () => {
  it('should reject standard GET GraphQL requests with 405 and Allow: POST', async () => {
    const response = await axios.get(`${API_URI}/graphql`, {
      params: { query: '{ __typename }' },
      validateStatus: () => true,
    });

    expect(response.status).toBe(405);
    expect(response.headers.allow).toBe('POST');
    expect(response.data?.name).toBe('MethodNotAllowedError');
  });
});
