import React, { useState } from 'react';
import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseThreatsField from './DefenseThreatsField';
import type { DefenseThreatOption } from './defenseMatrix-utils';

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

const accessAnswer = (edges: unknown[]) => ({ toPromise: () => Promise.resolve({ stixDomainObjects: { edges } }) });

const STORED: DefenseThreatOption[] = [
  { value: 'threat-renamed', label: 'Stored name', type: 'Intrusion-Set' },
  { value: 'threat-revoked', label: 'Revoked threat', type: 'Malware' },
];

const Field = ({ onChange }: { onChange: (threats: DefenseThreatOption[]) => void }) => {
  const [value, setValue] = useState(STORED);
  const handleChange = (next: DefenseThreatOption[]) => {
    onChange(next);
    setValue(next);
  };
  return <DefenseThreatsField value={value} onChange={handleChange} />;
};

describe('Defense threats field', () => {
  it('should show a stored threat only once the reader can access it, with its current name', async () => {
    mockFetchQuery.mockReturnValue({
      toPromise: () => Promise.resolve({
        stixDomainObjects: { edges: [{ node: { id: 'threat-renamed', entity_type: 'Intrusion-Set', representative: { main: 'Current name' } } }] },
      }),
    });
    const onChange = vi.fn();
    testRender(<Field onChange={onChange} />);
    // Nothing of the stored scope is shown before the answer
    expect(screen.queryByText('Stored name')).not.toBeInTheDocument();
    expect(screen.queryByText('Revoked threat')).not.toBeInTheDocument();
    expect(await screen.findByText('Current name')).toBeInTheDocument();
    expect(mockFetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      filters: { mode: 'and', filters: [{ key: ['ids'], values: ['threat-renamed', 'threat-revoked'] }], filterGroups: [] },
      first: 2,
    }));
    // The threat the reader can no longer access leaves the scope, the other one keeps its current name
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith([{ value: 'threat-renamed', label: 'Current name', type: 'Intrusion-Set' }]);
    expect(screen.queryByText('Stored name')).not.toBeInTheDocument();
    expect(screen.queryByText('Revoked threat')).not.toBeInTheDocument();
  });

  it('should keep the stored threats hidden when their access cannot be checked', async () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.reject(new Error('unavailable')) });
    const onChange = vi.fn();
    testRender(<Field onChange={onChange} />);
    await waitFor(() => expect(mockFetchQuery).toHaveBeenCalled());
    expect(screen.queryByText('Stored name')).not.toBeInTheDocument();
    expect(screen.queryByText('Revoked threat')).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('should confirm the stored threats again for another account', async () => {
    mockAccount.id = 'reader-1';
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue(accessAnswer([{ node: { id: 'threat-renamed', entity_type: 'Intrusion-Set', representative: { main: 'Stored name' } } }]));
    const { rerender } = testRender(<DefenseThreatsField value={[STORED[0]]} onChange={vi.fn()} />);
    expect(await screen.findByText('Stored name')).toBeInTheDocument();
    expect(mockFetchQuery).toHaveBeenCalledTimes(1);
    // The next account cannot access the threat: it is not shown before its own answer, then leaves the scope
    mockFetchQuery.mockReturnValue(accessAnswer([]));
    mockAccount.id = 'reader-2';
    const onChange = vi.fn();
    rerender(<DefenseThreatsField value={[STORED[0]]} onChange={onChange} />);
    expect(screen.queryByText('Stored name')).not.toBeInTheDocument();
    await waitFor(() => expect(onChange).toHaveBeenCalledWith([]));
    expect(mockFetchQuery).toHaveBeenCalledTimes(2);
  });
});
