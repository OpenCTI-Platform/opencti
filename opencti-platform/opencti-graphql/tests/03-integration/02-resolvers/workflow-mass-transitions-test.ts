import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';

const MASS_TRANSITIONS_QUERY = gql`
  query WorkflowMassTransitions($entityType: String!, $entityIds: [String!]) {
    workflowMassTransitions(entityType: $entityType, entityIds: $entityIds) {
      event
      toState
    }
  }
`;

const WORKFLOW_STATUSES_QUERY = gql`
  query WorkflowStatuses($entityType: String!) {
    workflowStatuses(entityType: $entityType) {
      id
    }
  }
`;

describe('Workflow mass transitions resolver', () => {
  it('should be readable by a knowledge editor without the customization capability', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR, { query: MASS_TRANSITIONS_QUERY, variables: { entityType: 'Report', entityIds: [] } });
    expect(result.data?.workflowMassTransitions).toEqual([]);
  });

  it('should be forbidden to a user who cannot update knowledge', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: MASS_TRANSITIONS_QUERY, variables: { entityType: 'Report', entityIds: [] } });
  });

  it('should list the workflow statuses for a knowledge editor', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR, { query: WORKFLOW_STATUSES_QUERY, variables: { entityType: 'Report' } });
    expect(result.data?.workflowStatuses).toEqual([]);
  });

  it('should refuse the workflow statuses to a user who cannot update knowledge', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: WORKFLOW_STATUSES_QUERY, variables: { entityType: 'Report' } });
  });
});
