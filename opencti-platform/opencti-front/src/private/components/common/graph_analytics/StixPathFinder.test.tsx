import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixPathFinder from './StixPathFinder';
import { fetchQuery, handleError } from '../../../../relay/environment';

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: vi.fn(() => ({ toPromise: () => Promise.resolve({ stixNeighborhoodSummary: null }) })),
  handleError: vi.fn(),
}));

const renderPathFinder = () => testRender(
  <StixPathFinder fromId="lynx" fromLabel="Sandstorm Lynx" toId="viper" toLabel="Coral Viper" renderActions={() => null} />,
  { userContext: createMockUserContext({ schema: { scrs: [], sdos: [], scos: [] } }) },
);

describe('StixPathFinder', () => {
  it('explains every setting of the search and links to the documentation of the path finder', () => {
    renderPathFinder();
    expect(screen.getByText(/^One hop is one relationship/)).toBeInTheDocument();
    expect(screen.getByText(/^How many paths to list, the shortest first/)).toBeInTheDocument();
    expect(screen.getByText(/^Only follow these relationships, for example/)).toBeInTheDocument();
    expect(screen.getByText(/^Only go through these entity types between the two entities/)).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Include inferred relationships' })).toHaveAccessibleDescription(/created by the inference rules/);
    expect(screen.getByRole('switch', { name: 'Go through containers' })).toHaveAccessibleDescription(/a case that contains them both/);
    expect(screen.getByTestId('graph-path-learn-more')).toHaveAttribute(
      'href',
      'https://docs.opencti.io/latest/usage/graph-analytics/#find-paths-between-two-entities',
    );
  });

  it('reports a failed search and lets the analyst search again', async () => {
    const failure = new Error('Search timed out');
    vi.mocked(fetchQuery).mockImplementation(((_query: unknown, variables: Record<string, unknown>) => ({
      toPromise: () => ('toId' in variables ? Promise.reject(failure) : Promise.resolve({ stixNeighborhoodSummary: null })),
    })) as unknown as typeof fetchQuery);
    const { user } = renderPathFinder();
    await user.click(screen.getByTestId('graph-path-find'));
    await waitFor(() => expect(handleError).toHaveBeenCalledWith(failure));
    expect(screen.getByTestId('graph-path-find')).toBeEnabled();
  });
});
