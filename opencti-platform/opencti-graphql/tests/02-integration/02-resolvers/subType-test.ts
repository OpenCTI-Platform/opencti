import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { isSorted, queryAsAdmin } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT } from '../../../src/schema/stixDomainObject';
import { STIX_CYBER_OBSERVABLES } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import type { TypeAttribute } from '../../../src/generated/graphql';
import type { BasicStoreEntityEdge } from '../../../src/types/store';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

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
                request_access_workflow {
                    approved_workflow_id
                    declined_workflow_id
                    workflow
                }
                requestAccessStatus {
                    id
                    color
                    name
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
        }
    }
`;

describe('SubType resolver standard behavior', () => {
  it('should list subTypes with type Stix-Cyber-Observable', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { type: 'Stix-Cyber-Observable' } });
    expect(queryResult.data?.subTypes.edges.length).toEqual(STIX_CYBER_OBSERVABLES.length);
    expect(isSorted(queryResult.data?.subTypes.edges.map((edge: BasicStoreEntityEdge<any>) => edge.node.id))).toEqual(true);
  });
  it('should list default subTypes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data?.subTypes.edges.length).toEqual(43);
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

    const requestAccessWorkflowConfiguration = queryResult?.data?.subType.settings.request_access_workflow;
    expect(requestAccessWorkflowConfiguration.workflow.length).toEqual(2); // 2 status: accepted and declined
    expect(requestAccessWorkflowConfiguration.approved_workflow_id).toBeDefined();
    expect(requestAccessWorkflowConfiguration.declined_workflow_id).toBeDefined();

    const requestAccessStatus = queryResult?.data?.subType.settings.requestAccessStatus;
  });
});
