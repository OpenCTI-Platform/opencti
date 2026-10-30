import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const retentionRulesQuery = (search: string) => `
  query {
    retentionRules(search: "${search}") {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const deleteRetentionRuleMutation = (id: string) => `
  mutation {
    retentionRuleEdit(id: "${id}") {
      delete
    }
  }
`;

/**
 * Delete every retention rule whose name starts with the given prefix.
 * Used as a guaranteed test cleanup: an active leaked retention rule
 * applies platform-wide and would be picked up by the retention manager.
 */
export const deleteRetentionRulesByName = async (request: APIRequestContext, namePrefix: string) => {
  const response = await graphqlQuery(request, retentionRulesQuery(namePrefix));
  const data = await response.json();
  const rules = (data.data?.retentionRules?.edges ?? [])
    .map((e: { node: { id: string; name: string } }) => e.node)
    .filter((node: { id: string; name: string }) => node.name.startsWith(namePrefix));
  for (const rule of rules) {
    await graphqlQuery(request, deleteRetentionRuleMutation(rule.id));
  }
};
