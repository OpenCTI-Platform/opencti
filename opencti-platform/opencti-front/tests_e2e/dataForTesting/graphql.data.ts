import { APIRequestContext } from '@playwright/test';

interface GraphQLResponse<T> {
  data?: T;
  errors?: Array<{ message: string }>;
}

/**
 * Posts a GraphQL document and returns its `data`, failing loudly on any error.
 *
 * The seeding used to fire its mutations without reading the responses, so a rejected write
 * (or a request that never reached the platform) only surfaced minutes later, as an unrelated
 * failure in whichever test first relied on the missing data. Every seeding call goes through
 * here so the run fails at init, on the mutation that failed, with its message.
 */
export const graphqlRequest = async <T>(request: APIRequestContext, query: string, description: string): Promise<T> => {
  const response = await request.post('/graphql', { data: { query } });
  if (!response.ok()) {
    throw new Error(`${description}: HTTP ${response.status()} ${response.statusText()}`);
  }
  const body = JSON.parse((await response.body()).toString()) as GraphQLResponse<T>;
  if (body.errors && body.errors.length > 0) {
    throw new Error(`${description}: ${body.errors.map((e) => e.message).join('; ')}`);
  }
  if (body.data === undefined || body.data === null) {
    throw new Error(`${description}: empty response`);
  }
  return body.data;
};
