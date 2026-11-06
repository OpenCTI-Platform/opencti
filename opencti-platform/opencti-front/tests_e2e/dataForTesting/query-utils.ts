import { APIRequestContext } from '@playwright/test';

const GRAPHQL_PATH = `${process.env.APP__BASE_PATH ?? ''}/graphql`;

export async function graphqlQuery(request: APIRequestContext, query: string) {
  return request.post(GRAPHQL_PATH, {
    data: { query },
  });
}

interface GraphqlResponse<T> {
  data?: T | null;
  errors?: { message: string; extensions?: { code?: string } }[];
}

export async function executeGraphql<T>(
  request: APIRequestContext,
  operation: string,
  query: string,
  variables?: Record<string, unknown>,
): Promise<T> {
  const response = await request.post(GRAPHQL_PATH, { data: { query, variables } });
  if (!response.ok()) {
    throw new Error(`${operation} failed: HTTP ${response.status()}`);
  }
  const result: GraphqlResponse<T> = await response.json();
  if (result.errors?.length) {
    const errors = result.errors.map(({ message, extensions }) => (
      extensions?.code ? `${extensions.code}: ${message}` : message
    ));
    throw new Error(`${operation} failed: ${errors.join('; ')}`);
  }
  if (result.data == null) {
    throw new Error(`${operation} failed: response has no data`);
  }
  return result.data;
}
