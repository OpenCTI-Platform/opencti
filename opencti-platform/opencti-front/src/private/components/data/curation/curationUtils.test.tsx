import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import useCurationLabels, { formatPercent, parseJsonObject } from './curationUtils';
import CurationConfidence from './CurationConfidence';

describe('parseJsonObject', () => {
  it('reads a JSON object', () => {
    expect(parseJsonObject('{"keep_actor_id":"a"}')).toEqual({ keep_actor_id: 'a' });
  });

  it('refuses anything that is not a JSON object', () => {
    expect(parseJsonObject(null)).toBeNull();
    expect(parseJsonObject('')).toBeNull();
    expect(parseJsonObject('[1,2]')).toBeNull();
    expect(parseJsonObject('"text"')).toBeNull();
    expect(parseJsonObject('{not json')).toBeNull();
  });
});

describe('formatPercent', () => {
  it('formats a ratio as a percentage', () => {
    expect(formatPercent(0.8567)).toEqual('86%');
    expect(formatPercent(0.8567, 1)).toEqual('85.7%');
    expect(formatPercent(0)).toEqual('0%');
  });

  it('shows a dash for a missing value', () => {
    expect(formatPercent(null)).toEqual('-');
    expect(formatPercent(undefined)).toEqual('-');
    expect(formatPercent(Number.NaN)).toEqual('-');
  });
});

const LabelsProbe = () => {
  const labels = useCurationLabels();
  return (
    <ul>
      <li>{labels.kind('merge')}</li>
      <li>{labels.kind('unknown_kind')}</li>
      <li>{labels.status(null)}</li>
      <li>{labels.action('add_aliases')}</li>
      <li>{labels.exclusion('below_threshold')}</li>
      <li>{labels.impact('merge:Intrusion-Set')}</li>
      <li>{labels.weekDay(1)}</li>
      <li data-testid="open-color">{labels.statusColor('open')}</li>
      <li data-testid="healthy-color">{labels.healthColor(95)}</li>
      <li data-testid="unhealthy-color">{labels.healthColor(10)}</li>
    </ul>
  );
};

describe('useCurationLabels', () => {
  it('translates the curation vocabulary and keeps unknown keys readable', () => {
    testRender(<LabelsProbe />);
    expect(screen.getByText('Duplicate')).toBeInTheDocument();
    expect(screen.getByText('unknown_kind')).toBeInTheDocument();
    expect(screen.getByText('-')).toBeInTheDocument();
    expect(screen.getByText('Add the names as aliases')).toBeInTheDocument();
    expect(screen.getByText('Confidence below the threshold')).toBeInTheDocument();
    expect(screen.getByText(/^Duplicate - /)).toBeInTheDocument();
    expect(screen.getByText('Monday')).toBeInTheDocument();
  });

  it('gives distinct colors to a healthy and an unhealthy score', () => {
    testRender(<LabelsProbe />);
    const healthy = screen.getByTestId('healthy-color').textContent;
    const unhealthy = screen.getByTestId('unhealthy-color').textContent;
    expect(healthy).not.toEqual('');
    expect(healthy).not.toEqual(unhealthy);
    expect(screen.getByTestId('open-color').textContent).not.toEqual('');
  });
});

const EXPLAINED = [
  {
    evidence_type: 'trigram',
    score: 0.9,
    description: 'stored trigram',
    details: { left_name: 'Fancy Bear', right_name: 'Fancy Bears', similarity: 0.91 },
  },
  {
    evidence_type: 'attribution_conflict',
    score: 1,
    description: 'stored attribution',
    details: {
      attributed_name: 'Campaign X',
      actor_names: ['Actor A', 'Actor B'],
    },
  },
  {
    // Recorded before the count was kept: 50 identifiers may stand for more shared techniques.
    evidence_type: 'attack_overlap',
    score: 0.4,
    description: 'stored overlap',
    details: { shared_ids: Array.from({ length: 50 }, (_, index) => `technique-${index}`), left_count: 80, right_count: 90 },
  },
  { evidence_type: 'future_signal', score: 1, description: 'stored future signal', details: null },
];

const ExplanationProbe = () => {
  const labels = useCurationLabels();
  return (
    <ul>
      {EXPLAINED.map((item) => <li key={item.evidence_type}>{labels.explanation(item, item.details)}</li>)}
    </ul>
  );
};

describe('evidence explanations', () => {
  it('builds each explanation from the parameters its detector recorded', () => {
    testRender(<ExplanationProbe />);
    expect(screen.getByText('"Fancy Bear" and "Fancy Bears" are 91% similar (trigram similarity)')).toBeInTheDocument();
    expect(screen.getByText(
      '"Campaign X" is attributed to "Actor A" and to "Actor B": these actors were decided to be distinct and no source attributes it to both',
    )).toBeInTheDocument();
  });

  it('keeps the stored explanation when a parameter is missing or the evidence type is unknown', () => {
    testRender(<ExplanationProbe />);
    expect(screen.getByText('stored overlap')).toBeInTheDocument();
    expect(screen.getByText('stored future signal')).toBeInTheDocument();
  });
});

describe('CurationConfidence', () => {
  it('shows the confidence as a percentage with an accessible bar', () => {
    testRender(<CurationConfidence value={0.72} />);
    expect(screen.getByText('72%')).toBeInTheDocument();
    expect(screen.getByRole('progressbar', { name: 'Curation confidence' })).toHaveAttribute('aria-valuenow', '72');
  });

  it('marks a proposal that needs a decision', () => {
    testRender(<CurationConfidence value={0.6} ambiguous />);
    expect(screen.getByTitle('Needs your decision: the evidence is not conclusive')).toBeInTheDocument();
  });
});
