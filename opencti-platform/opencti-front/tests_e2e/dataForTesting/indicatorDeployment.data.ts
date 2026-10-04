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
  errorMessage?: string,
) => {
  const metadata = errorMessage ? `, metadata: { error_message: ${JSON.stringify(errorMessage)} }` : '';
  const response = await graphqlQuery(request, `
    mutation {
      indicatorReportDeployment(indicatorId: "${indicatorId}", platformId: "${platformId}", status: ${status}${metadata}) {
        id
      }
    }
  `);
  return (await response.json()).data.indicatorReportDeployment.id as string;
};

export const registerIocValidationConnector = async (request: APIRequestContext, id: string, name: string) => {
  return graphqlQuery(request, `
    mutation {
      registerConnector(input: {
        id: "${id}",
        name: "${name}",
        type: INTERNAL_ENRICHMENT,
        scope: ["ioc-validation-request"],
        auto: false,
        auto_update: false
      }) {
        id
      }
    }
  `);
};

export const deleteConnector = async (request: APIRequestContext, id: string) => {
  return graphqlQuery(request, `mutation { deleteConnector(id: "${id}") }`);
};

export const requestValidation = async (
  request: APIRequestContext,
  name: string,
  platformId: string,
  indicatorIds: string[],
  connectorId: string,
) => {
  const response = await graphqlQuery(request, `
    mutation {
      indicatorsRequestValidation(
        platformIds: ["${platformId}"],
        indicatorIds: [${indicatorIds.map((id) => `"${id}"`).join(', ')}],
        testKinds: [dns_resolution],
        connectorId: "${connectorId}",
        name: "${name}"
      ) {
        id
      }
    }
  `);
  return (await response.json()).data.indicatorsRequestValidation.id as string;
};

export const reportValidationResults = async (
  request: APIRequestContext,
  requestId: string,
  platformId: string,
  results: Array<{ indicatorId: string; status: 'detected' | 'prevented' | 'missed' }>,
) => {
  return graphqlQuery(request, `
    mutation {
      iocValidationReportResults(
        id: "${requestId}",
        platformId: "${platformId}",
        results: [${results.map((result) => `{ indicatorId: "${result.indicatorId}", status: ${result.status} }`).join(', ')}]
      ) {
        id
      }
    }
  `);
};

export const completeValidationRequest = async (request: APIRequestContext, requestId: string) => {
  return graphqlQuery(request, `
    mutation {
      iocValidationRequestStatusUpdate(id: "${requestId}", input: { status: completed }) {
        id
      }
    }
  `);
};

export const deleteValidationRequest = async (request: APIRequestContext, requestId: string) => {
  return graphqlQuery(request, `mutation { iocValidationRequestDelete(id: "${requestId}") }`);
};
