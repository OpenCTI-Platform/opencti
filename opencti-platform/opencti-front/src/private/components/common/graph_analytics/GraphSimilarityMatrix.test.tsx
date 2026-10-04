import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import GraphSimilarityMatrix from './GraphSimilarityMatrix';

const entities = [
  { id: 'a', entity_type: 'Intrusion-Set', representative: { main: 'APT A' } },
  { id: 'b', entity_type: 'Intrusion-Set', representative: { main: 'APT B' } },
  { id: 'c', entity_type: 'Intrusion-Set', representative: { main: 'APT C' } },
];
const cells = [
  { source_id: 'a', target_id: 'b', score: 0.62, shared_count: 4 },
  { source_id: 'b', target_id: 'a', score: 0.62, shared_count: 4 },
  { source_id: 'a', target_id: 'c', score: 0, shared_count: 0 },
  { source_id: 'c', target_id: 'a', score: 0, shared_count: 0 },
  { source_id: 'b', target_id: 'c', score: 0.1, shared_count: 1 },
  { source_id: 'c', target_id: 'b', score: 0.1, shared_count: 1 },
];

describe('GraphSimilarityMatrix', () => {
  it('asks for more entities when there is nothing to compare', () => {
    testRender(<GraphSimilarityMatrix entities={entities.slice(0, 1)} cells={[]} />);
    expect(screen.getByText('Select at least two entities to compare them')).toBeInTheDocument();
  });

  it('renders one labelled cell per ordered pair with the score as a percentage', () => {
    testRender(<GraphSimilarityMatrix entities={entities} cells={cells} />);
    expect(screen.getByTestId('graph-similarity-matrix')).toBeInTheDocument();
    expect(screen.getAllByLabelText('APT A and APT B: 62% similar, 4 shared elements')).toHaveLength(1);
    expect(screen.getAllByLabelText('APT B and APT A: 62% similar, 4 shared elements')).toHaveLength(1);
    expect(screen.getAllByLabelText('APT B and APT C: 10% similar, 1 shared element')).toHaveLength(1);
    expect(screen.getAllByLabelText('APT A and APT C: 0% similar, 0 shared elements')).toHaveLength(1);
    expect(screen.getAllByText('62')).toHaveLength(2);
    expect(screen.getAllByText('10')).toHaveLength(2);
  });

  it('links each row to its entity, unless links are disabled for public dashboards', () => {
    const { unmount } = testRender(<GraphSimilarityMatrix entities={entities} cells={cells} />);
    expect(screen.getByRole('link', { name: 'APT A' })).toHaveAttribute('href', '/dashboard/threats/intrusion_sets/a');
    unmount();
    testRender(<GraphSimilarityMatrix entities={entities} cells={cells} disableLinks />);
    expect(screen.queryByRole('link', { name: 'APT A' })).not.toBeInTheDocument();
    expect(screen.getAllByText('APT A').length).toBeGreaterThan(0);
  });
});
