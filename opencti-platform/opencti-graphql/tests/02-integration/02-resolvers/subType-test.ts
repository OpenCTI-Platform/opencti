import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, isSorted, queryAsAdmin, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT } from '../../../src/schema/stixDomainObject';
import { STIX_CYBER_OBSERVABLES } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { StatusScope, type TypeAttribute } from '../../../src/generated/graphql';
import type { BasicStoreEntity, BasicStoreEntityEdge } from '../../../src/types/store';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { pageEntitiesConnection } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';
import { QUERY_REQUEST_ACCESS_SETTINGS } from './requestAccess-test';

const LIST_QUERY = gql`
  query subTypes($type: String) {
    subTypes(type: $type) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const SUB_TYPE_ATTRIBUTES_QUERY = gql`
  query subType($id: String!) {
    subType(id: $id) {
      settings {
        attributesDefinitions {
          name
        }
        mandatoryAttributes
      }
    }
  }
`;

const SUB_TYPE_FIND_BY_ID_QUERY = gql`
    query subType($id: String!) {
        subType(id: $id) {
            id
            label
            workflowEnabled
            settings {
                id
                availableSettings
                requestAccessConfiguration {
                    approved_status {
                        id
                        template {
                            id
                            name
                        }
                    }
                    declined_status {
                        id
                        template {
                            id
                            name
                        }
                    }
                    approval_admin {
                        id
                        name
                    }
                }
            }
            statuses {
                id
                order
                template {
                    name
                    color
                }
            }
            statusesRequestAccess {
                id
                order
                template {
                    name
                    color
                }
            }
        }
    }
`;

export const MUTATION_ENABLE_RFI_WORKFLOW = gql`
    mutation SubTypeWorkflowStatusAddCreationMutation(
        $id: ID!
        $input: StatusAddInput!
    ) {
        subTypeEdit(id: $id) {
            statusAdd(input: $input) {
                id
                label
                workflowEnabled
                statuses {
                    id
                    order
                    template {
                        name
                        color
                        id
                    }
                }
            }
        }
    }`;

describe('SubType resolver standard behavior', () => {
  it('should list subTypes with type Stix-Cyber-Observable', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { type: 'Stix-Cyber-Observable' } });
    expect(queryResult.data?.subTypes.edges.length).toEqual(STIX_CYBER_OBSERVABLES.length);
    expect(isSorted(queryResult.data?.subTypes.edges.map((edge: BasicStoreEntityEdge<any>) => edge.node.id))).toEqual(true);
  });
  it('should list default subTypes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data?.subTypes.edges.length).toEqual(45);
    expect(isSorted(queryResult.data?.subTypes.edges.map((edge: BasicStoreEntityEdge<any>) => edge.node.id))).toEqual(true);
  });
  it('should retrieve mandatory attribute for an entity', async () => {
    const queryResult = await queryAsAdmin({ query: SUB_TYPE_ATTRIBUTES_QUERY, variables: { id: ENTITY_TYPE_DATA_COMPONENT } });
    const attributesDefinitions = queryResult?.data?.subType.settings.attributesDefinitions;
    expect(attributesDefinitions.map((attr: TypeAttribute) => attr.name).includes('name')).toBeTruthy();
    expect(attributesDefinitions.length).toEqual(5);
    const mandatoryAttributes = queryResult?.data?.subType.settings.mandatoryAttributes;
    expect(mandatoryAttributes.includes('name')).toBeTruthy();
    expect(mandatoryAttributes.length).toEqual(1);
  });
});

describe('SubType resolver for RFI and request access use case', () => {
  it('should request access configuration for case RFI exists', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: SUB_TYPE_FIND_BY_ID_QUERY, variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI } });

    const requestAccessWorkflowConfiguration = queryResult?.data?.subType.settings.requestAccessConfiguration;
    expect(requestAccessWorkflowConfiguration.approved_status.id).toBeDefined();
    expect(requestAccessWorkflowConfiguration.approved_status.template.name).toBe('APPROVED');
    expect(requestAccessWorkflowConfiguration.declined_status.id).toBeDefined();
    expect(requestAccessWorkflowConfiguration.declined_status.template.name).toBe('DECLINED');
  });

  it('should statuses list only global workflow statuses (and not request-access one)', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: SUB_TYPE_FIND_BY_ID_QUERY, variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI } });
    const workflowStatuses = queryResult.data?.subType.statuses;
    // From data-initalization we do expect some status
    expect(workflowStatuses.some((status: any) => status.template.name === 'DECLINED')).toBeFalsy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'APPROVED')).toBeFalsy();
  });
});

describe('SubType resolver for RFI use case', () => {
  it('should RFI workflow enabled with at least one status', async () => {
    const statusTemplateId_NEW = await pageEntitiesConnection<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"NEW"' });
    expect(statusTemplateId_NEW.edges[0].node.name).toBe('NEW');
    expect(statusTemplateId_NEW.edges[0].node.internal_id).toBeDefined();
    const newStatusId = statusTemplateId_NEW.edges[0].node.internal_id;

    const statusTemplateId_IN_PROGRESS = await pageEntitiesConnection<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { search: '"IN_PROGRESS"' });
    const inProgressStatusId = statusTemplateId_IN_PROGRESS.edges[0].node.internal_id;

    // To verify 'NEW' usage, let's have 2 status created in reverse order.
    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 2,
          template_id: inProgressStatusId,
          scope: StatusScope.Global,
        }
      },
    });

    await queryAsAdminWithSuccess({
      query: MUTATION_ENABLE_RFI_WORKFLOW,
      variables: {
        id: ENTITY_TYPE_CONTAINER_CASE_RFI,
        input: {
          order: 0,
          template_id: newStatusId,
          scope: StatusScope.Global,
        }
      },
    });
    const rfiEntitySettingsWithWorkflow = await queryAsAdminWithSuccess({
      query: QUERY_REQUEST_ACCESS_SETTINGS,
      variables: { id: ENTITY_TYPE_CONTAINER_CASE_RFI },
    });

    expect(rfiEntitySettingsWithWorkflow?.data?.subType.workflowEnabled).toBeTruthy();

    // only workflow 'GLOBAL' scope statuses should be in statuses, not request-access one
    const workflowStatuses = rfiEntitySettingsWithWorkflow?.data?.subType.statuses;
    expect(workflowStatuses.some((status: any) => status.template.name === 'NEW')).toBeTruthy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'IN_PROGRESS')).toBeTruthy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'DECLINED')).toBeFalsy();
    expect(workflowStatuses.some((status: any) => status.template.name === 'APPROVED')).toBeFalsy();

    // only workflow 'REQUEST_ACCESS' scope statuses should be in statusesRequestAccess, not workflow one
    const requestAccessStatuses = rfiEntitySettingsWithWorkflow?.data?.subType.statusesRequestAccess;
    expect(requestAccessStatuses.some((status: any) => status.template.name === 'NEW')).toBeTruthy();
    expect(requestAccessStatuses.some((status: any) => status.template.name === 'IN_PROGRESS')).toBeFalsy();
    expect(requestAccessStatuses.some((status: any) => status.template.name === 'DECLINED')).toBeTruthy();
    expect(requestAccessStatuses.some((status: any) => status.template.name === 'APPROVED')).toBeTruthy();
  });
});
