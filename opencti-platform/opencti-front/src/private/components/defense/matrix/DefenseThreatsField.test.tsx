import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseThreatsField from './DefenseThreatsField';
import { DEFENSE_MAX_SELECTED_THREATS } from './defenseMatrix-utils';

const mockFetchQuery = vi.fn();
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
}));

// The account of the reader, changed without a remount as when another user logs in
const mockAccount = { id: 'reader-1' };
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../utils/hooks/useAuth')>();
  return {
    ...original,
    default: () => {
      const auth = original.default();
      return { ...auth, me: { ...auth.me, id: mockAccount.id } };
    },
  };
});

const searchAnswer = (edges: unknown[]) => ({ toPromise: () => Promise.resolve({ stixDomainObjects: { edges } }) });

describe('Defense threats field', () => {
  it('should never show the search results of another account', async () => {
    mockAccount.id = 'reader-1';
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue(searchAnswer([{ node: { id: 'threat-1', entity_type: 'Intrusion-Set', representative: { main: 'Threat of reader 1' } } }]));
    const { user, rerender } = testRender(<DefenseThreatsField value={[]} onChange={vi.fn()} />);
    await user.type(screen.getByTestId('defense-threats-input'), 'a');
    expect(await screen.findByText('Threat of reader 1')).toBeInTheDocument();
    mockFetchQuery.mockReturnValue(searchAnswer([]));
    mockAccount.id = 'reader-2';
    rerender(<DefenseThreatsField value={[]} onChange={vi.fn()} />);
    expect(screen.queryByText('Threat of reader 1')).not.toBeInTheDocument();
  });

  it('should drop a search answer arriving after a change of account', async () => {
    mockAccount.id = 'reader-1';
    mockFetchQuery.mockReset();
    let answerFirstReader: (data: unknown) => void = () => {};
    mockFetchQuery.mockReturnValueOnce({
      toPromise: () => new Promise((resolve) => {
        answerFirstReader = resolve;
      }),
    });
    mockFetchQuery.mockReturnValue(searchAnswer([]));
    const { user, rerender } = testRender(<DefenseThreatsField value={[]} onChange={vi.fn()} />);
    await user.type(screen.getByTestId('defense-threats-input'), 'a');
    await waitFor(() => expect(mockFetchQuery).toHaveBeenCalledTimes(1));
    mockAccount.id = 'reader-2';
    rerender(<DefenseThreatsField value={[]} onChange={vi.fn()} />);
    answerFirstReader({ stixDomainObjects: { edges: [{ node: { id: 'threat-1', entity_type: 'Intrusion-Set', representative: { main: 'Threat of reader 1' } } }] } });
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByText('Threat of reader 1')).not.toBeInTheDocument();
  });

  it('should stop the selection at the limit the API applies, and say why', async () => {
    mockAccount.id = 'reader-1';
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue(searchAnswer([
      { node: { id: 'threat-0', entity_type: 'Malware', representative: { main: 'Threat 0' } } },
      { node: { id: 'threat-other', entity_type: 'Malware', representative: { main: 'Other threat' } } },
    ]));
    const selected = Array.from({ length: DEFENSE_MAX_SELECTED_THREATS }, (_, index) => ({ value: `threat-${index}`, label: `Threat ${index}`, type: 'Malware' }));
    const { user } = testRender(<DefenseThreatsField value={selected} onChange={vi.fn()} />);
    expect(screen.getByTestId('defense-threats-limit')).toBeInTheDocument();
    await user.type(screen.getByTestId('defense-threats-input'), 't');
    // A selected threat can still be removed, no other one can be added
    expect((await screen.findByText('Other threat')).closest('[role="option"]')).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByRole('option', { name: /Threat 0/ })).not.toHaveAttribute('aria-disabled', 'true');
  });

  it('should not mention the limit below it', () => {
    mockFetchQuery.mockReset();
    const selected = [{ value: 'threat-1', label: 'Threat 1', type: 'Malware' }];
    testRender(<DefenseThreatsField value={selected} onChange={vi.fn()} />);
    expect(screen.queryByTestId('defense-threats-limit')).not.toBeInTheDocument();
  });
});
