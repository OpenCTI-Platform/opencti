import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SubTypeWorkflow from './SubTypeWorkflow';

const mockLoadQuery = vi.fn();
let mockQueryVariables: unknown[] = [];

vi.mock('../../../../utils/hooks/useQueryLoading', () => ({
  default: vi.fn(() => ({})),
  useQueryLoadingWithLoadQuery: vi.fn((_query: unknown, variables: unknown) => {
    mockQueryVariables.push(variables);
    return [{}, mockLoadQuery];
  }),
}));

vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    usePreloadedQuery: vi.fn(() => ({ workflowDefinition: null })),
  };
});

vi.mock('../../Error', () => ({
  ErrorBoundary: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('./workflow/Workflow', () => ({
  default: ({ entityType, scope, onScopeChange }: { entityType: string; scope: string; onScopeChange: (scope: string) => void }) => (
    <div>
      <span data-testid="editor">{`${entityType}:${scope}`}</span>
      <button onClick={() => onScopeChange('REQUEST_ACCESS')}>to request access</button>
    </div>
  ),
}));

const lastVariables = () => mockQueryVariables.at(-1);

describe('SubTypeWorkflow scope', () => {
  beforeEach(() => {
    mockQueryVariables = [];
  });

  it('opens on the Global scope', () => {
    render(<SubTypeWorkflow entityType="Case-Rfi" />);

    expect(screen.getByTestId('editor')).toHaveTextContent('Case-Rfi:GLOBAL');
    expect(lastVariables()).toEqual({ entityType: 'Case-Rfi', allowDraft: true, scope: 'GLOBAL' });
  });

  it('queries and edits the request access scope on Case-Rfi once picked', async () => {
    const user = userEvent.setup();
    render(<SubTypeWorkflow entityType="Case-Rfi" />);

    await user.click(screen.getByText('to request access'));

    expect(screen.getByTestId('editor')).toHaveTextContent('Case-Rfi:REQUEST_ACCESS');
    expect(lastVariables()).toEqual({ entityType: 'Case-Rfi', allowDraft: true, scope: 'REQUEST_ACCESS' });
  });

  it('always uses the Global scope for any other entity type', async () => {
    const user = userEvent.setup();
    render(<SubTypeWorkflow entityType="Case-Rfd" />);

    // Even if the editor asked for it, the backend throws on REQUEST_ACCESS outside Case-Rfi.
    await user.click(screen.getByText('to request access'));

    expect(screen.getByTestId('editor')).toHaveTextContent('Case-Rfd:GLOBAL');
    expect(mockQueryVariables.every((variables) => (variables as { scope: string }).scope === 'GLOBAL')).toBe(true);
  });

  it('reopens Case-Rfi on the Global scope after another entity type', async () => {
    const user = userEvent.setup();
    const { rerender } = render(<SubTypeWorkflow entityType="Case-Rfi" />);
    await user.click(screen.getByText('to request access'));
    expect(screen.getByTestId('editor')).toHaveTextContent('Case-Rfi:REQUEST_ACCESS');

    rerender(<SubTypeWorkflow entityType="Case-Rfd" />);
    rerender(<SubTypeWorkflow entityType="Case-Rfi" />);

    expect(screen.getByTestId('editor')).toHaveTextContent('Case-Rfi:GLOBAL');
    expect(lastVariables()).toEqual({ entityType: 'Case-Rfi', allowDraft: true, scope: 'GLOBAL' });
  });
});
