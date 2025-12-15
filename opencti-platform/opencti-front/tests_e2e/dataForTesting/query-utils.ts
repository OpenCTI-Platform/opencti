import { APIRequestContext } from '@playwright/test';

export async function graphqlQuery(request: APIRequestContext, query: string) {
  return request.post('/graphql', {
    data: { query },
  });
}
