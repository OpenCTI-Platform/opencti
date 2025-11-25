import { APIRequestContext } from '@playwright/test';

// oxlint-disable-next-line import/prefer-default-export
export async function graphqlQuery(request: APIRequestContext, query: string) {
  return request.post('/graphql', {
    data: { query },
  });
}
