import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

export const addIndicator = async (request: APIRequestContext, value: string) => {
  const response = await graphqlQuery(request, `
    mutation {
      indicatorAdd(input: {
        name: "${value}",
        pattern: "[domain-name:value = '${value}']",
        pattern_type: "stix",
        x_opencti_main_observable_type: "Domain-Name"
      }) {
        id
      }
    }
  `);
  return (await response.json()).data.indicatorAdd.id as string;
};

export const deleteIndicator = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `mutation { indicatorDelete(id: "${id}") }`);
};

export const addSecurityPlatform = async (request: APIRequestContext, name: string) => {
  const response = await graphqlQuery(request, `
    mutation {
      securityPlatformAdd(input: { name: "${name}", security_platform_type: "SIEM" }) {
        id
      }
    }
  `);
  return (await response.json()).data.securityPlatformAdd.id as string;
};

export const deleteSecurityPlatform = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `mutation { securityPlatformDelete(id: "${id}") }`);
};

export const reportDeployment = async (
  request: APIRequestContext,
  indicatorId: string,
  platformId: string,
  status: 'pending' | 'deployed' | 'active' | 'failed' | 'removed',
) => {
  const response = await graphqlQuery(request, `
    mutation {
      indicatorReportDeployment(indicatorId: "${indicatorId}", platformId: "${platformId}", status: ${status}) {
        id
      }
    }
  `);
  return (await response.json()).data.indicatorReportDeployment.id as string;
};
