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

  it('hides a result and its actions once a search parameter changes, and drops an answer that comes after the change', async () => {
    const paths = {
      max_depth: 4,
      depth_reached: 1,
      explored_nodes: 2,
      explored_relationships: 1,
      truncated: false,
      timed_out: false,
      duration_ms: 12,
      paths: [{
        length: 1,
        node_ids: ['lynx', 'viper'],
        relationship_ids: ['uses-1'],
        relationship_types: ['uses'],
        nodes: [
          { id: 'lynx', entity_type: 'Intrusion-Set', representative: { main: 'Sandstorm Lynx' } },
          { id: 'viper', entity_type: 'Malware', representative: { main: 'Coral Viper' } },
        ],
        relationships: [{ id: 'uses-1', fromId: 'lynx' }],
      }],
    };
    let answerLate: (value: unknown) => void = () => {};
    let searches = 0;
    vi.mocked(fetchQuery).mockImplementation(((_query: unknown, variables: Record<string, unknown>) => ({
      toPromise: () => {
        if (!('toId' in variables)) return Promise.resolve({ stixNeighborhoodSummary: null });
        searches += 1;
        if (searches === 1) return Promise.resolve({ stixPaths: paths });
        return new Promise((resolve) => {
          answerLate = resolve;
        });
      },
    })) as unknown as typeof fetchQuery);
    const { user } = testRender(
      <StixPathFinder fromId="lynx" fromLabel="Sandstorm Lynx" toId="viper" toLabel="Coral Viper" renderActions={() => <button type="button">Start investigation</button>} />,
      { userContext: createMockUserContext({ schema: { scrs: [], sdos: [], scos: [] } }) },
    );
    await user.click(screen.getByTestId('graph-path-find'));
    await waitFor(() => expect(screen.getByTestId('graph-path-results')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Start investigation' })).toBeInTheDocument();
    // The paths belong to the previous parameters: they can no longer start an investigation
    await user.click(screen.getByRole('switch', { name: 'Include inferred relationships' }));
    expect(screen.queryByTestId('graph-path-results')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start investigation' })).not.toBeInTheDocument();
    // A search still running when its parameters change is dropped when it answers
    await user.click(screen.getByTestId('graph-path-find'));
    await user.click(screen.getByRole('switch', { name: 'Go through containers' }));
    answerLate({ stixPaths: paths });
    await waitFor(() => expect(screen.getByTestId('graph-path-find')).toBeEnabled());
    expect(screen.queryByTestId('graph-path-results')).not.toBeInTheDocument();
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
