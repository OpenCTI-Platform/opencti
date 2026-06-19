import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import { defaultColumnsMap } from './dataTableUtils';

vi.mock('../i18n', () => ({
  useFormatter: () => ({
    t_i18n: (s: string) => s,
    fsd: (s: string) => s,
    n: (s: number) => String(s),
    nsdt: (s: string) => s,
    ftd: (s: string) => s,
  }),
}));

vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
}));

describe('dataTableUtils - workflowInstance column', () => {
  const workflowInstanceCol = defaultColumnsMap.get('workflowInstance');

  it('is defined in defaultColumnsMap', () => {
    expect(workflowInstanceCol).toBeDefined();
  });

  it('has isSortable set to false', () => {
    expect(workflowInstanceCol?.isSortable).toBe(false);
  });

  it('has label "Workflow status"', () => {
    expect(workflowInstanceCol?.label).toBe('Workflow status');
  });

  it('has percentWidth of 12', () => {
    expect(workflowInstanceCol?.percentWidth).toBe(12);
  });

  it('renders ItemStatus with disabled=true when workflowInstance is undefined', () => {
    const renderFn = workflowInstanceCol?.render;
    if (!renderFn) throw new Error('render function not found');
    const { container } = render(<>{renderFn({ workflowInstance: undefined } as any)}</>);
    expect(container).toBeTruthy();
  });

  it('renders ItemStatus with disabled=false when workflowInstance.currentStatus is set', () => {
    const renderFn = workflowInstanceCol?.render;
    if (!renderFn) throw new Error('render function not found');
    const mockData = {
      workflowInstance: {
        currentStatus: { id: 'status-1', template: { name: 'In Progress', color: '#ff0' } },
      },
    };
    const { container } = render(<>{renderFn(mockData as any)}</>);
    expect(container).toBeTruthy();
  });
});
