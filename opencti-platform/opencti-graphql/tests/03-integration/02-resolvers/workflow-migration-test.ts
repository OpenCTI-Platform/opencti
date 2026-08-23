import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { findTemplatePaginated } from '../../../src/domain/status';
import { StatusScope, type StatusAddInput } from '../../../src/generated/graphql';
import { migrateEntityTypeStatusToWorkflowDefinition } from '../../../src/modules/workflow/migration/migrate-status-to-workflow-definition';
import { executionContext } from '../../../src/utils/access';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

// `migrateEntityTypeStatusToWorkflowDefinition` (like several workflow-module domain functions)
// reads `context.user` internally (via `bypassDraftContext`) instead of the separately-passed
// `user` argument - this always holds true on the real GraphQL request path, where `context.user`
// is set by the same `executionContext(source, auth)` call that supplies `user`, but the shared
// `testContext` used across this test suite is built without a `.user` (`executionContext(...)`
// called with no `auth`), so it must not be used here - build a dedicated context with `.user` set.
const migrationTestContext = executionContext('workflow-migration-test', ADMIN_USER);

// Task 6, Step 3.2 / tasks.md 6.5: `Incident` has no default legacy Status data (unlike `Report`/
// `Case-Rfi`, seeded at platform init - see data-initialization.js's createDefaultStatusTemplates)
// and no test elsewhere in this suite configures a real WorkflowDefinition for it, making it a
// safe, isolated entity type to seed fresh Status data on for this migration test.
const MIGRATION_ENTITY_TYPE = 'Incident';

const ADD_STATUS_MUTATION = gql`
  mutation AddIncidentStatusForMigrationTest($id: ID!, $input: StatusAddInput!) {
    subTypeEdit(id: $id) {
      statusAdd(input: $input) {
        id
      }
    }
  }
`;

const DELETE_STATUS_MUTATION = gql`
  mutation DeleteIncidentStatusForMigrationTest($id: ID!, $statusId: ID!) {
    subTypeEdit(id: $id) {
      statusDelete(statusId: $statusId) {
        id
      }
    }
  }
`;

const WORKFLOW_MIGRATION_PREVIEW_QUERY = gql`
  query WorkflowMigrationPreviewForMigrationTest($entityType: String!) {
    workflowMigrationPreview(entityType: $entityType) {
      entityType
      results {
        scope
        initialState
        states {
          statusId
        }
        transitions {
          from
          to
          event
        }
        diagnostics {
          type
          message
        }
      }
    }
  }
`;

const WORKFLOW_DEFINITION_QUERY = gql`
  query WorkflowDefinitionForMigrationTest($entityType: String!) {
    workflowDefinition(entityType: $entityType) {
      published
      initialState
      states {
        statusId
      }
      transitions {
        from
        to
        event
      }
    }
  }
`;

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDeleteForMigrationTest($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      workflow_id
    }
  }
`;

describe('Workflow migration preview vs actual migration (tasks.md 6.5)', () => {
  let newStatusId: string;
  let inProgressStatusId: string;

  beforeAll(async () => {
    const templates = await findTemplatePaginated(testContext, ADMIN_USER, {});
    const newTemplate = templates.edges.find((edge) => edge.node.name === 'NEW');
    const progressTemplate = templates.edges.find((edge) => edge.node.name === 'IN_PROGRESS');
    expect(newTemplate).toBeDefined();
    expect(progressTemplate).toBeDefined();

    const newInput: StatusAddInput = { order: 1, scope: StatusScope.Global, template_id: newTemplate!.node.id };
    const newResult = await queryAsAdminWithSuccess({
      query: ADD_STATUS_MUTATION,
      variables: { id: MIGRATION_ENTITY_TYPE, input: newInput },
    });
    newStatusId = newResult.data.subTypeEdit.statusAdd.id;

    const progressInput: StatusAddInput = { order: 2, scope: StatusScope.Global, template_id: progressTemplate!.node.id };
    const progressResult = await queryAsAdminWithSuccess({
      query: ADD_STATUS_MUTATION,
      variables: { id: MIGRATION_ENTITY_TYPE, input: progressInput },
    });
    inProgressStatusId = progressResult.data.subTypeEdit.statusAdd.id;
  });

  afterAll(async () => {
    // Definition must be deleted before the underlying Status records, otherwise statusDelete
    // rejects with 'Cannot delete a status that is used in a published or draft workflow'.
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: { entityType: MIGRATION_ENTITY_TYPE },
    });
    await queryAsAdmin({
      query: DELETE_STATUS_MUTATION,
      variables: { id: MIGRATION_ENTITY_TYPE, statusId: newStatusId },
    });
    await queryAsAdmin({
      query: DELETE_STATUS_MUTATION,
      variables: { id: MIGRATION_ENTITY_TYPE, statusId: inProgressStatusId },
    });
  });

  it('preview should reflect the seeded legacy Status data with no diagnostics', async () => {
    const preview = await queryAsAdminWithSuccess({
      query: WORKFLOW_MIGRATION_PREVIEW_QUERY,
      variables: { entityType: MIGRATION_ENTITY_TYPE },
    });
    const globalResult = preview.data.workflowMigrationPreview.results.find((result: any) => result.scope === 'GLOBAL');
    expect(globalResult).toBeDefined();
    expect(globalResult.states.length).toBe(2);
    expect(globalResult.transitions.length).toBeGreaterThan(0);
    expect(globalResult.diagnostics.length).toBe(0);
  });

  it('actual migration output should exactly match the preview', async () => {
    const preview = await queryAsAdminWithSuccess({
      query: WORKFLOW_MIGRATION_PREVIEW_QUERY,
      variables: { entityType: MIGRATION_ENTITY_TYPE },
    });
    const globalResult = preview.data.workflowMigrationPreview.results.find((result: any) => result.scope === 'GLOBAL');

    const migrationResult = await migrateEntityTypeStatusToWorkflowDefinition(migrationTestContext, ADMIN_USER, MIGRATION_ENTITY_TYPE);
    expect(migrationResult).toEqual({ entityType: MIGRATION_ENTITY_TYPE, status: 'migrated' });

    const actual = await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: { entityType: MIGRATION_ENTITY_TYPE },
    });
    expect(actual.data.workflowDefinition.published).toBe(true);
    expect(actual.data.workflowDefinition.initialState).toBe(globalResult.initialState);
    expect(actual.data.workflowDefinition.states.map((state: any) => state.statusId).sort())
      .toEqual(globalResult.states.map((state: any) => state.statusId).sort());
    expect(actual.data.workflowDefinition.transitions.length).toBe(globalResult.transitions.length);
    for (const transition of globalResult.transitions) {
      expect(actual.data.workflowDefinition.transitions).toContainEqual(transition);
    }
  });

  it('migration should be idempotent, skipping an entity type that already has a WorkflowDefinition', async () => {
    const result = await migrateEntityTypeStatusToWorkflowDefinition(migrationTestContext, ADMIN_USER, MIGRATION_ENTITY_TYPE);
    expect(result).toEqual({ entityType: MIGRATION_ENTITY_TYPE, status: 'skipped_already_migrated' });
  });
});
