import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const idOf = async (response: Awaited<ReturnType<typeof graphqlQuery>>, field: string): Promise<string> => {
  const body = await response.json();
  const id = body?.data?.[field]?.id;
  if (!id) throw new Error(`${field} did not return an id: ${JSON.stringify(body?.errors ?? body)}`);
  return id;
};

export const addCaseIncident = async (request: APIRequestContext, name: string) => {
  const response = await graphqlQuery(request, `
    mutation { caseIncidentAdd(input: { name: "${name}" }) { id } }
  `);
  return idOf(response, 'caseIncidentAdd');
};

export const deleteCaseIncident = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `mutation { caseIncidentDelete(id: "${id}") }`);
};

export const addIndicator = async (request: APIRequestContext, name: string, ip: string) => {
  const response = await graphqlQuery(request, `
    mutation {
      indicatorAdd(input: {
        name: "${name}",
        pattern: "[ipv4-addr:value = '${ip}']",
        pattern_type: "stix",
        x_opencti_main_observable_type: "IPv4-Addr"
      }) { id }
    }
  `);
  return idOf(response, 'indicatorAdd');
};

export const deleteStixDomainObject = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `mutation { stixDomainObjectEdit(id: "${id}") { delete } }`);
};

export const deleteInvestigationPolicyByName = async (request: APIRequestContext, name: string) => {
  const response = await graphqlQuery(request, `
    query { investigationPolicies(first: 100, search: "${name}") { edges { node { id name } } } }
  `);
  const body = await response.json();
  const edges: { node: { id: string; name: string } }[] = body?.data?.investigationPolicies?.edges ?? [];
  await Promise.all(edges
    .filter((edge) => edge.node.name === name)
    .map((edge) => graphqlQuery(request, `mutation { investigationPolicyDelete(id: "${edge.node.id}") }`)));
};
