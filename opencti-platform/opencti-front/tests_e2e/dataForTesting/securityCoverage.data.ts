import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const getData = async (response: Awaited<ReturnType<typeof graphqlQuery>>) => {
  return (await response.json()).data;
};

export const addAttackPattern = async (request: APIRequestContext, name: string): Promise<string> => {
  const response = await graphqlQuery(request, `
    mutation {
      attackPatternAdd(input: { name: "${name}" }) {
        id
      }
    }
  `);
  return (await getData(response)).attackPatternAdd.id;
};

export const deleteAttackPattern = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `
    mutation {
      attackPatternEdit(id: "${id}") {
        delete
      }
    }
  `);
};

export const addSecurityCoverage = async (
  request: APIRequestContext,
  input: { name: string; objectCovered: string },
): Promise<string> => {
  const response = await graphqlQuery(request, `
    mutation {
      securityCoverageAdd(input: {
        name: "${input.name}",
        objectCovered: "${input.objectCovered}",
        auto_enrichment_disable: true
      }) {
        id
      }
    }
  `);
  return (await getData(response)).securityCoverageAdd.id;
};

export const deleteSecurityCoverage = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `
    mutation {
      securityCoverageDelete(id: "${id}")
    }
  `);
};

export const addSecurityCoverageResult = async (
  request: APIRequestContext,
  input: { name: string; resultOf: string; coveredIds: string[] },
): Promise<string> => {
  const response = await graphqlQuery(request, `
    mutation {
      securityCoverageResultAdd(input: {
        name: "${input.name}",
        resultOf: "${input.resultOf}",
        coverage_information: [{ coverage_name: "detection", coverage_score: 50 }],
        add_related_entities: { selected_ids: [${input.coveredIds.map((id) => `"${id}"`).join(', ')}] }
      }) {
        id
      }
    }
  `);
  return (await getData(response)).securityCoverageResultAdd.id;
};

/**
 * Fetch the name of a security coverage result and the names of the
 * entities it covers (targets of its has-covered relationships).
 */
export const getSecurityCoverageResult = async (
  request: APIRequestContext,
  id: string,
): Promise<{ name: string; coveredNames: string[] }> => {
  const response = await graphqlQuery(request, `
    query {
      securityCoverageResult(id: "${id}") {
        name
        stixCoreRelationships(relationship_type: "has-covered") {
          edges {
            node {
              to {
                ... on AttackPattern {
                  name
                }
              }
            }
          }
        }
      }
    }
  `);
  const result = (await getData(response)).securityCoverageResult;
  return {
    name: result.name,
    coveredNames: result.stixCoreRelationships.edges.map(({ node }: { node: { to: { name: string } } }) => node.to.name),
  };
};
