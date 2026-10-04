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
