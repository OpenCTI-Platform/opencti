import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixDomainObjectOverview from './StixDomainObjectOverview';

const { readFragment, transitions } = vi.hoisted(() => ({ readFragment: vi.fn(), transitions: vi.fn() }));

vi.mock('../workflow/WorkflowStatus.graphql', () => ({ workflowStatusFragment: {}, workflowStatusStixDomainObjectFragment: {} }));
vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_fragment: unknown, data: unknown) => readFragment(data),
}));
vi.mock('../workflow/WorkflowTransitions', () => ({
  WorkflowTransitions: () => null,
  WorkflowTransitionsForEntity: ({ data }: { data: unknown }) => {
    transitions(data);
    return <button>Apply transition</button>;
  },
}));
vi.mock('../../analyses/opinions/StixCoreObjectOpinions', () => ({ default: () => null }));
vi.mock('../../cases/case_rfis/ProcessingStatusOverview', () => ({ default: () => <span>Request access status</span> }));

const makeEntity = (entityType = 'Report', requestAccess = false) => ({
  id: 'entity-1', entity_type: entityType, standard_id: 'report--1', x_opencti_stix_ids: [],
  objectMarking: [], createdBy: null, x_opencti_reliability: null, confidence: 50,
  created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z', created_at: '2024-01-01T00:00:00.000Z',
  status: { id: 'legacy-1', template: { name: 'Legacy status', color: '#ff0000' } }, workflowEnabled: true,
  objectAssignee: [], objectParticipant: [], revoked: false, objectLabel: [], creators: [],
  x_opencti_request_access: requestAccess, __fragments: { WorkflowStatusStixDomainObject_data: {} },
});

const renderOverview = ({ enabled = true, configured = true, capabilities = ['KNOWLEDGE_KNUPDATE'], entityType = 'Report', requestAccess = false, currentUserAccessRight = 'edit' } = {}) => {
  const entity = { ...makeEntity(entityType, requestAccess), currentUserAccessRight };
  const resolved = {
    id: entity.id, entity_type: entityType, currentUserAccessRight,
    workflowInstance: configured ? {
      id: 'instance-1', currentStatus: { id: 'workflow-status-1', template: { name: 'Workflow status', color: '#00ff00' } }, lastHistoryEntry: null,
    } : null,
  };
  readFragment.mockImplementation((reference) => {
    expect(reference).toBe(entity);
    return resolved;
  });
  testRender(<StixDomainObjectOverview stixDomainObject={entity} displayOpinions={false} />, {
    userContext: createMockUserContext({
      me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [] },
      settings: { platform_feature_flags: enabled ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
      entitySettings: { edges: [] },
    }),
  });
  return entity;
};

beforeEach(() => vi.clearAllMocks());

describe('StixDomainObjectOverview workflow', () => {
  it('retains the legacy status with the flag off without reading the workflow fragment', () => {
    renderOverview({ enabled: false });
    expect(screen.getByText('Legacy status')).toBeVisible();
    expect(readFragment).not.toHaveBeenCalled();
    expect(transitions).not.toHaveBeenCalled();
  });

  it('retains the legacy status and hides actions without a configured workflow', () => {
    renderOverview({ configured: false, capabilities: ['BYPASS'] });
    expect(screen.getByText('Legacy status')).toBeVisible();
    expect(transitions).not.toHaveBeenCalled();
  });

  it.each(['Report', 'Incident', 'Case-Rfi'])('shows configured %s status and passes the original reference to transitions', (entityType) => {
    const entity = renderOverview({ entityType });
    expect(screen.getByText('Workflow status')).toBeVisible();
    expect(screen.queryByText('Legacy status')).toBeNull();
    expect(screen.getByRole('button', { name: 'Apply transition' })).toBeVisible();
    expect(transitions).toHaveBeenCalledWith(entity);
  });

  it('keeps the status visible for read-only users without mounting action components', () => {
    renderOverview({ capabilities: [] });
    expect(screen.getByText('Workflow status')).toBeVisible();
    expect(transitions).not.toHaveBeenCalled();
  });

  it('passes the original reference to the shared controls for BYPASS users', () => {
    const entity = renderOverview({ capabilities: ['BYPASS'] });
    expect(screen.getByRole('button', { name: 'Apply transition' })).toBeVisible();
    expect(transitions).toHaveBeenCalledWith(entity);
  });

  it('keeps status but hides controls with global update capability and entity view access', () => {
    renderOverview({ currentUserAccessRight: 'view' });
    expect(screen.getByText('Workflow status')).toBeVisible();
    expect(transitions).not.toHaveBeenCalled();
  });

  it('preserves the RequestAccess exclusion', () => {
    renderOverview({ entityType: 'Case-Rfi', requestAccess: true, capabilities: ['BYPASS'] });
    expect(screen.getByText('Request access status')).toBeVisible();
    expect(screen.queryByText('Processing status')).toBeNull();
    expect(readFragment).not.toHaveBeenCalled();
    expect(transitions).not.toHaveBeenCalled();
  });
});
