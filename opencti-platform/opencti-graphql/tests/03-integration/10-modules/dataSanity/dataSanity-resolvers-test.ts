import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
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

const DATA_SANITY_CONFIGURATION_QUERY = gql`
  query DataSanityConfiguration {
    settings {
      data_sanity_configuration {
        maintenance_planning {
          day
          start_time
          end_time
        }
        timezone_offset
      }
    }
  }
`;

const DATA_SANITY_REQUEST_RUN_MUTATION = gql`
  mutation DataSanityOperationRequestRun($operation_name: String!) {
    dataSanityOperationRequestRun(operation_name: $operation_name)
  }
`;

const DATA_SANITY_UPDATE_PLANNING_MUTATION = gql`
  mutation DataSanityUpdateMaintenancePlanning($planning: [DataSanityMaintenanceWindowInput!]!, $timezone_offset: Int!) {
    dataSanityUpdateMaintenancePlanning(planning: $planning, timezone_offset: $timezone_offset) {
      maintenance_planning {
        day
        start_time
        end_time
      }
      timezone_offset
    }
  }
`;

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

    it('should return data sanity configuration (nullable)', async () => {
      const result = await queryAsAdminWithSuccess({ query: DATA_SANITY_CONFIGURATION_QUERY });
      // Configuration may or may not exist depending on test order
      // Just verify the query resolves without error
      const config = result.data.settings.data_sanity_configuration;
      if (config) {
        expect(Array.isArray(config.maintenance_planning)).toBeTruthy();
        expect(typeof config.timezone_offset).toBe('number');
      }
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

    it('should update maintenance planning', async () => {
      const planning = [
        { day: 'monday', start_time: '08:00', end_time: '12:00' },
        { day: 'wednesday', start_time: '22:00', end_time: '04:00' },
      ];
      const result = await queryAsAdminWithSuccess({
        query: DATA_SANITY_UPDATE_PLANNING_MUTATION,
        variables: { planning, timezone_offset: 120 },
      });
      const config = result.data.dataSanityUpdateMaintenancePlanning;
      expect(config).toBeDefined();
      expect(config.timezone_offset).toBe(120);
      expect(config.maintenance_planning).toHaveLength(2);
      expect(config.maintenance_planning[0]).toMatchObject({ day: 'monday', start_time: '08:00', end_time: '12:00' });
      expect(config.maintenance_planning[1]).toMatchObject({ day: 'wednesday', start_time: '22:00', end_time: '04:00' });
    });

    it('should update maintenance planning with empty array', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DATA_SANITY_UPDATE_PLANNING_MUTATION,
        variables: { planning: [], timezone_offset: 0 },
      });
      const config = result.data.dataSanityUpdateMaintenancePlanning;
      expect(config).toBeDefined();
      expect(config.maintenance_planning).toHaveLength(0);
      expect(config.timezone_offset).toBe(0);
    });

    it('should verify force_run was set after requesting run', async () => {
      // The previous mutation set force_run, verify via operations query
      const result = await queryAsAdminWithSuccess({ query: DATA_SANITY_OPERATIONS_QUERY });
      const operation = result.data.dataSanityOperations.find(
        (op: any) => op.identifier === 'caseSensitiveDuplicatedId',
      );
      expect(operation).toBeDefined();
      // force_run should be true (set by the earlier mutation)
      expect(operation.force_run).toBe(true);
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

    it('should forbid dataSanityUpdateMaintenancePlanning mutation for non-bypass user', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DATA_SANITY_UPDATE_PLANNING_MUTATION,
        variables: {
          planning: [{ day: 'monday', start_time: '08:00', end_time: '12:00' }],
          timezone_offset: 0,
        },
      });
    });
  });
});
