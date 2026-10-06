import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { defaultColumnsMap } from './dataTableUtils';
import type { DataTableColumn } from './dataTableTypes';

const handleAddFilter = vi.fn();
const legacyStatus = { id: 'status-1', template: { name: 'Legacy status', color: '#ff0000' } };
const workflowStatus = { id: 'status-2', template: { name: 'Workflow status', color: '#00ff00' } };

// Public dashboards render without an authenticated user context.
const publicUserContext = { locale: 'en-us', tz: 'UTC', unitSystem: 'Metric' } as const;

const renderColumn = (columnId: string, data: Record<string, unknown>, { flag = false, isPublic = false } = {}) => {
  const render = defaultColumnsMap.get(columnId)?.render;
  if (!render) throw new Error(`No render for column ${columnId}`);
  const helpers = { storageHelpers: { handleAddFilter } } as unknown as Parameters<NonNullable<DataTableColumn['render']>>[1];
  return testRender(<>{render(data, helpers)}</>, {
    userContext: isPublic ? publicUserContext : createMockUserContext({
      settings: { platform_feature_flags: flag ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
    }),
  });
};

describe('dataTableUtils status columns', () => {
  it('workflowInstance column renders the workflow status of a draft', () => {
    renderColumn('workflowInstance', {
      entity_type: 'DraftWorkspace',
      workflowInstance: { id: 'instance-1', currentStatus: workflowStatus },
    });
    expect(screen.getByText('Workflow status')).toBeInTheDocument();
  });

  it('workflowInstance column renders a disabled status when the draft has no workflow instance', () => {
    renderColumn('workflowInstance', { entity_type: 'DraftWorkspace', workflowInstance: null });
    expect(screen.getByText('Disabled')).toBeInTheDocument();
  });

  it('keeps the workflow status of a draft whose instance is not persisted yet', () => {
    renderColumn('workflowInstance', {
      entity_type: 'DraftWorkspace',
      workflowInstance: { id: 'initial-draft-1', currentStatus: workflowStatus },
    });
    expect(screen.getByText('Workflow status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column renders the legacy status when no workflow instance is selected', () => {
    renderColumn('x_opencti_workflow_id', { entity_type: 'Report', status: legacyStatus, workflowEnabled: true }, { flag: true });
    expect(screen.getByText('Legacy status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column renders the workflow status when the flag is on', () => {
    renderColumn('x_opencti_workflow_id', {
      entity_type: 'Report',
      status: legacyStatus,
      workflowEnabled: true,
      workflowInstance: { id: 'instance-1', currentStatus: workflowStatus },
    }, { flag: true });
    expect(screen.getByText('Workflow status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column renders the legacy status when the flag is off', () => {
    renderColumn('x_opencti_workflow_id', {
      entity_type: 'Report',
      status: legacyStatus,
      workflowEnabled: true,
      workflowInstance: { id: 'instance-1', currentStatus: workflowStatus },
    });
    expect(screen.getByText('Legacy status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column renders the legacy status when the workflow instance is not persisted yet', () => {
    renderColumn('x_opencti_workflow_id', {
      entity_type: 'Report',
      status: legacyStatus,
      workflowEnabled: true,
      workflowInstance: { id: 'initial-report-1', currentStatus: workflowStatus },
    }, { flag: true });
    expect(screen.getByText('Legacy status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column renders the legacy status on public dashboards', () => {
    renderColumn('x_opencti_workflow_id', { entity_type: 'Report', status: legacyStatus, workflowEnabled: true }, { isPublic: true });
    expect(screen.getByText('Legacy status')).toBeInTheDocument();
  });

  it('x_opencti_workflow_id column adds a filter when the legacy status is clicked', async () => {
    const { user } = renderColumn('x_opencti_workflow_id', { entity_type: 'Report', status: legacyStatus, workflowEnabled: true });
    await user.click(screen.getByText('Legacy status'));
    expect(handleAddFilter).toHaveBeenCalled();
  });
});
