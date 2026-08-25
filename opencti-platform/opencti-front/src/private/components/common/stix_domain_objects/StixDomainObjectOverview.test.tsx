import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixDomainObjectOverview from './StixDomainObjectOverview';

// Task 9: this test focuses only on the new "Processing status" branching logic added to mount
// the generic StixDomainObject-bound workflow UI (WorkflowStatusForEntity / WorkflowTransitionsForEntity
// / WorkflowBypassStatus) instead of the legacy read-only ItemStatus, when an entity is managed by a
// published WorkflowDefinition. The workflow components themselves are unit-tested in
// WorkflowStatus.test.tsx / WorkflowBypassStatus.test.tsx, so they're stubbed out here.
//
// `stixDomainObject` here is a plain JS object, not a real Relay fragment reference, so the
// `useFragment(workflowStatusStixDomainObjectFragment, stixDomainObject)` call this component makes
// to unmask `workflowInstance` (Relay data masking) must be stubbed to just return its input as-is.
vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});

vi.mock('../workflow/WorkflowStatus', () => ({
  WorkflowStatusForEntity: ({ entityType }: { entityType: string }) => (
    <div data-testid="workflow-status-for-entity">{entityType}</div>
  ),
  WorkflowTransitionsForEntity: ({ entityType }: { entityType: string }) => (
    <div data-testid="workflow-transitions-for-entity">{entityType}</div>
  ),
  WorkflowClosingReasonForEntity: ({ entityType }: { entityType: string }) => (
    <div data-testid="workflow-closing-reason-for-entity">{entityType}</div>
  ),
}));

vi.mock('../workflow/WorkflowBypassStatus', () => ({
  WorkflowBypassStatus: ({ entityId, children }: { entityId: string; children?: React.ReactNode }) => (
    <div data-testid="workflow-bypass-status">
      {entityId}
      {children}
    </div>
  ),
}));

vi.mock('../../analyses/opinions/StixCoreObjectOpinions', () => ({ default: () => null }));
vi.mock('../../cases/case_rfis/ProcessingStatusOverview', () => ({ default: () => null }));

const withEntitiesWorkflowFlag = (enable: boolean) => createMockUserContext({
  settings: { platform_feature_flags: enable ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
  entitySettings: { edges: [] },
});

const makeStixDomainObject = (overrides: Record<string, unknown> = {}) => ({
  id: 'entity-1',
  entity_type: 'Report',
  standard_id: 'report--1',
  x_opencti_stix_ids: [],
  objectMarking: [],
  createdBy: null,
  x_opencti_reliability: null,
  confidence: 50,
  created: '2024-01-01T00:00:00.000Z',
  modified: '2024-01-01T00:00:00.000Z',
  created_at: '2024-01-01T00:00:00.000Z',
  pattern_type: null,
  status: null,
  workflowEnabled: true,
  workflowInstance: null,
  objectAssignee: [],
  objectParticipant: [],
  revoked: false,
  objectLabel: [],
  creators: [],
  x_opencti_request_access: false,
  ...overrides,
});

describe('StixDomainObjectOverview - Processing status', () => {
  it('renders the legacy ItemStatus when there is no workflowInstance', () => {
    testRender(
      <StixDomainObjectOverview
        stixDomainObject={makeStixDomainObject()}
        displayOpinions={false}
      />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(screen.queryByTestId('workflow-status-for-entity')).toBeNull();
  });

  it('renders the legacy ItemStatus when the ENTITIES_WORKFLOW flag is off, even with a workflowInstance', () => {
    testRender(
      <StixDomainObjectOverview
        stixDomainObject={makeStixDomainObject({ workflowInstance: { id: 'instance-1' } })}
        displayOpinions={false}
      />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(screen.queryByTestId('workflow-status-for-entity')).toBeNull();
  });

  it('mounts the generic workflow status/transitions/bypass components when a workflowInstance exists and the flag is on', () => {
    testRender(
      <StixDomainObjectOverview
        stixDomainObject={makeStixDomainObject({ workflowInstance: { id: 'instance-1' } })}
        displayOpinions={false}
      />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(screen.getByTestId('workflow-status-for-entity')).toHaveTextContent('Report');
    expect(screen.getByTestId('workflow-transitions-for-entity')).toHaveTextContent('Report');
    expect(screen.getByTestId('workflow-bypass-status')).toHaveTextContent('entity-1');
  });
});
