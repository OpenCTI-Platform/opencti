import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { StixPathChain, type StixPathResult } from './StixPathFinder';

const node = (id: string, name: string, entityType: string) => ({ id, entity_type: entityType, representative: { main: name } });

describe('StixPathChain', () => {
  it('draws each relationship in its own direction', () => {
    // Sandstorm Lynx uses NightCrawler, and Coral Viper uses NightCrawler: the second link points back
    const path = {
      length: 2,
      node_ids: ['lynx', 'nightcrawler', 'viper'],
      relationship_ids: ['r1', 'r2'],
      relationship_types: ['uses', 'uses'],
      nodes: [node('lynx', 'Sandstorm Lynx', 'Intrusion-Set'), node('nightcrawler', 'NightCrawler', 'Malware'), node('viper', 'Coral Viper', 'Intrusion-Set')],
      relationships: [{ id: 'r1', fromId: 'lynx' }, { id: 'r2', fromId: 'viper' }],
    } as unknown as StixPathResult;
    testRender(<StixPathChain path={path} />);
    expect(screen.getByText('Sandstorm Lynx')).toBeInTheDocument();
    expect(screen.getAllByTestId('graph-path-link-forward')).toHaveLength(1);
    expect(screen.getAllByTestId('graph-path-link-backward')).toHaveLength(1);
  });
});
