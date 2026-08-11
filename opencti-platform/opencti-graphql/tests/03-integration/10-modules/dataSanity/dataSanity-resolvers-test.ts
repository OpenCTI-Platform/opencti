import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { USER_PARTICIPATE } from '../../../utils/testQuery';

const DATA_SANITY_OPERATIONS_QUERY = gql`
  query DataSanityOperations {
    dataSanityOperations {
      identifier
      display_name
      execution_type
      description
      eligible_entity_types
      is_running
      force_run
      last_run_date
      last_execution_time
      last_run_success
      last_run_message
      last_run_output
    }
  }
`;

const DATA_SANITY_EXECUTIONS_QUERY = gql`
  query DataSanityExecutions {
    dataSanityExecutions {
      operation_name
      last_run_date
      last_execution_time
      last_run_success
      last_run_message
      last_run_output
      force_run
    }
  }
`;

const DATA_SANITY_DRY_RUN_QUERY = gql`
  query DataSanityOperationDryRun($operation_name: String!) {
    dataSanityOperationDryRun(operation_name: $operation_name) {
      estimated_impact {
        key
        count
      }
    }
  }
`;

const DATA_SANITY_REQUEST_RUN_MUTATION = gql`
  mutation DataSanityOperationRequestRun($operation_name: String!) {
    dataSanityOperationRequestRun(operation_name: $operation_name)
  }
`;

const DATA_SANITY_STOP_MUTATION = gql`
  mutation DataSanityOperationStop($operation_name: String!) {
    dataSanityOperationStop(operation_name: $operation_name)
  }
`;

const findOperation = (operations: any[], identifier: string) => operations.find((op: any) => op.identifier === identifier);

describe('Data sanity resolvers test coverage', () => {
  describe('Queries', () => {
    it('should list all data sanity operations', async () => {
      const result = await queryAsAdminWithSuccess({ query: DATA_SANITY_OPERATIONS_QUERY });
      expect(result.data.dataSanityOperations).toBeDefined();
      expect(Array.isArray(result.data.dataSanityOperations)).toBeTruthy();
      expect(result.data.dataSanityOperations.length).toBeGreaterThan(0);

      const operation = result.data.dataSanityOperations[0];
      expect(operation.identifier).toBeDefined();
      expect(operation.display_name).toBeDefined();
      expect(operation.execution_type).toBeDefined();
      expect(operation.description).toBeDefined();
      expect(operation.eligible_entity_types).toBeDefined();
      expect(Array.isArray(operation.eligible_entity_types)).toBeTruthy();
      expect(typeof operation.is_running).toBe('boolean');
      expect(typeof operation.force_run).toBe('boolean');
    });

    it('should list all data sanity executions', async () => {
      const result = await queryAsAdminWithSuccess({ query: DATA_SANITY_EXECUTIONS_QUERY });
      expect(result.data.dataSanityExecutions).toBeDefined();
      expect(Array.isArray(result.data.dataSanityExecutions)).toBeTruthy();
    });

    it('should execute a dry run for a known operation', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DATA_SANITY_DRY_RUN_QUERY,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
      expect(result.data.dataSanityOperationDryRun).toBeDefined();
      expect(result.data.dataSanityOperationDryRun.estimated_impact).toBeDefined();
      expect(Array.isArray(result.data.dataSanityOperationDryRun.estimated_impact)).toBeTruthy();
    });
  });

  describe('Mutations', () => {
    it('should request a force run for an operation', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DATA_SANITY_REQUEST_RUN_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
      expect(result.data.dataSanityOperationRequestRun).toBeDefined();
      // Returns the internal_id of the execution entity
      expect(typeof result.data.dataSanityOperationRequestRun).toBe('string');
    });

    it('should verify force_run was set after requesting run', async () => {
      // The previous mutation set force_run, verify via operations query
      const result = await queryAsAdminWithSuccess({ query: DATA_SANITY_OPERATIONS_QUERY });
      const operation = findOperation(result.data.dataSanityOperations, 'caseSensitiveDuplicatedId');
      expect(operation).toBeDefined();
      // force_run should be true (set by the earlier mutation)
      expect(operation.force_run).toBe(true);
    });

    it('should stop a scheduled operation and mark it as done', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DATA_SANITY_STOP_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
      // Returns the internal_id of the execution entity
      expect(typeof result.data.dataSanityOperationStop).toBe('string');

      const operations = await queryAsAdminWithSuccess({ query: DATA_SANITY_OPERATIONS_QUERY });
      const operation = findOperation(operations.data.dataSanityOperations, 'caseSensitiveDuplicatedId');
      expect(operation).toBeDefined();
      // Marked as done: not running anymore and no pending force run
      expect(operation.is_running).toBe(false);
      expect(operation.force_run).toBe(false);
      expect(operation.last_run_date).toBeDefined();
      expect(operation.last_run_message).toEqual('Operation stopped manually');
    });

    it('should allow to schedule a stopped operation again', async () => {
      await queryAsAdminWithSuccess({
        query: DATA_SANITY_REQUEST_RUN_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
      const operations = await queryAsAdminWithSuccess({ query: DATA_SANITY_OPERATIONS_QUERY });
      const operation = findOperation(operations.data.dataSanityOperations, 'caseSensitiveDuplicatedId');
      expect(operation.force_run).toBe(true);

      // Cleanup: leave the operation in a stopped state for other tests
      await queryAsAdminWithSuccess({
        query: DATA_SANITY_STOP_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
    });

    it('should fail to stop an unknown operation', async () => {
      await queryAsAdminWithError(
        { query: DATA_SANITY_STOP_MUTATION, variables: { operation_name: 'unknownSanityOperation' } },
        'Unknown sanity operation: unknownSanityOperation',
      );
    });
  });

  describe('Access control - BYPASS capability required', () => {
    it('should forbid dataSanityOperations query for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: DATA_SANITY_OPERATIONS_QUERY });
    });

    it('should forbid dataSanityExecutions query for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: DATA_SANITY_EXECUTIONS_QUERY });
    });

    it('should forbid dataSanityOperationDryRun query for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DATA_SANITY_DRY_RUN_QUERY,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
    });

    it('should forbid dataSanityOperationRequestRun mutation for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DATA_SANITY_REQUEST_RUN_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
    });

    it('should forbid dataSanityOperationStop mutation for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DATA_SANITY_STOP_MUTATION,
        variables: { operation_name: 'caseSensitiveDuplicatedId' },
      });
    });
  });
});
