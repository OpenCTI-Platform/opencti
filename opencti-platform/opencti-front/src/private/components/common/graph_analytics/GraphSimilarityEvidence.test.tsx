import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import GraphSimilarityEvidence from './GraphSimilarityEvidence';

const entity = (id: string, main: string, entity_type = 'Attack-Pattern') => ({ id, entity_type, representative: { main } });

describe('GraphSimilarityEvidence', () => {
  it('says so when no shared element is visible', () => {
    testRender(<GraphSimilarityEvidence evidence={[]} />);
    expect(screen.getByText('No shared element you can access')).toBeInTheDocument();
  });

  it('groups the shared elements by family with their count', () => {
    testRender(
      <GraphSimilarityEvidence
        evidence={[
          { family: 'techniques', entities: [entity('t1', 'Phishing'), entity('t2', 'PowerShell')] },
          { family: 'malware', entities: [entity('m1', 'Cobalt Strike', 'Malware')] },
        ]}
      />,
    );
    expect(screen.getByText('Techniques (2)')).toBeInTheDocument();
    expect(screen.getByText('Malware (1)')).toBeInTheDocument();
    expect(screen.getByText('Phishing')).toBeInTheDocument();
    expect(screen.getByText('Cobalt Strike')).toBeInTheDocument();
  });

  it('caps the chips of a family and counts the hidden ones', () => {
    const many = Array.from({ length: 9 }, (_, i) => entity(`t${i}`, `Technique ${i}`));
    testRender(<GraphSimilarityEvidence evidence={[{ family: 'techniques', entities: many }]} maxPerFamily={4} />);
    expect(screen.getByText('Technique 3')).toBeInTheDocument();
    expect(screen.queryByText('Technique 4')).not.toBeInTheDocument();
    expect(screen.getByText('and 5 more')).toBeInTheDocument();
  });
});
