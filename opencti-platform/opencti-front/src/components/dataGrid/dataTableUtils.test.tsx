import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { defaultColumnsMap } from './dataTableUtils';
import type { DataTableColumn } from './dataTableTypes';

type ColumnHelpers = Parameters<NonNullable<DataTableColumn['render']>>[1];

const handleAddFilter = vi.fn();
const legacyStatus = { id: 'status-1', template: { name: 'Legacy status', color: '#ff0000' } };
const workflowStatus = { id: 'status-2', template: { name: 'Workflow status', color: '#00ff00' } };

// Public dashboards render without an authenticated user context.
const publicUserContext = { locale: 'en-us', tz: 'UTC', unitSystem: 'Metric' } as const;

const renderColumn = (
  columnId: string,
  data: unknown,
  { helpers = {}, flag = false, isPublic = false }: { helpers?: Record<string, unknown>; flag?: boolean; isPublic?: boolean } = {},
) => {
  const render = defaultColumnsMap.get(columnId)?.render;
  if (!render) throw new Error(`Column "${columnId}" has no render function`);
  const columnHelpers = { storageHelpers: { handleAddFilter }, ...helpers } as unknown as ColumnHelpers;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return testRender(<div>{render(data as any, columnHelpers)}</div>, {
    userContext: isPublic ? publicUserContext : createMockUserContext({
      settings: { platform_feature_flags: flag ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
    }),
  });
};

const fileData = (mimetype: string, size: number) => ({
  importFiles: { edges: [{ node: { name: 'sample.bin', metaData: { mimetype }, size } }] },
});

describe('dataTableUtils default columns — tooltip anchors', () => {
  it('anchors the color tooltip', async () => {
    const { user } = renderColumn('color', { color: '#ff7f50' });
    await user.hover(screen.getByText('#ff7f50'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('#ff7f50');
  });

  it('anchors the x_opencti_color tooltip', async () => {
    const { user } = renderColumn('x_opencti_color', { x_opencti_color: '#4b0082' });
    await user.hover(screen.getByText('#4b0082'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('#4b0082');
  });

  it('anchors the file_size tooltip, on the size the cell shows', async () => {
    const { user } = renderColumn('file_size', fileData('text/plain', 42), {
      helpers: { b: (value: number) => `${value} Bytes` },
    });
    await user.hover(screen.getByText('42 Bytes'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('42 Bytes');
  });

  it('anchors the number_observed tooltip', async () => {
    const { user } = renderColumn('number_observed', { number_observed: 7 }, {
      helpers: { n: (value: number) => `${value} times` },
    });
    await user.hover(screen.getByText('7 times'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('7');
  });

  it('anchors the operatingSystem tooltip', async () => {
    const { user } = renderColumn('operatingSystem', { operatingSystem: { name: 'Debian 12' } });
    await user.hover(screen.getByText('Debian 12'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Debian 12');
  });
});

describe('dataTableUtils default columns, allowed markings', () => {
  it('shows one marking chip and lists the others in the tooltip', async () => {
    const { user } = renderColumn('allowed_markings', {
      allowed_markings: [
        { id: 'm1', definition: 'PAP:RED' },
        { id: 'm2', definition: 'TLP:AMBER' },
        { id: 'm3', definition: 'PAP:AMBER' },
      ],
    });
    expect(screen.getByText('PAP:RED')).toBeInTheDocument();
    expect(screen.queryByText('TLP:AMBER')).not.toBeInTheDocument();
    expect(screen.queryByText('PAP:AMBER')).not.toBeInTheDocument();
    await user.hover(screen.getByText('PAP:RED'));
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('TLP:AMBER');
    expect(tooltip).toHaveTextContent('PAP:AMBER');
  });
});

describe('dataTableUtils status columns', () => {
  beforeEach(() => handleAddFilter.mockClear());

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

  it('x_opencti_workflow_id column adds a filter on the legacy status id when it is clicked', async () => {
    const { user } = renderColumn('x_opencti_workflow_id', { entity_type: 'Report', status: legacyStatus, workflowEnabled: true });
    await user.click(screen.getByText('Legacy status'));
    expect(handleAddFilter).toHaveBeenCalledTimes(1);
    expect(handleAddFilter).toHaveBeenCalledWith('x_opencti_workflow_id', 'status-1', 'eq', expect.objectContaining({ type: 'click' }));
  });

  it('x_opencti_workflow_id column adds a "no status" filter when an empty status is clicked', async () => {
    const { user } = renderColumn('x_opencti_workflow_id', { entity_type: 'Report', status: null, workflowEnabled: true });
    await user.click(screen.getByText('Unknown'));
    expect(handleAddFilter).toHaveBeenCalledWith('x_opencti_workflow_id', null, 'eq', expect.objectContaining({ type: 'click' }));
  });
});
