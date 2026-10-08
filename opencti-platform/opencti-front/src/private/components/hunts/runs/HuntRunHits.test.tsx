import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import HuntRunHits, { type HuntRunHit } from './HuntRunHits';

const hit = (index: number, recurrence: Partial<HuntRunHit> = {}): HuntRunHit => ({
  event_id: `evt-${index}`,
  timestamp: '2026-10-05T10:00:00Z',
  host: `ws-${index}`,
  user: 'jdoe',
  process: 'powershell.exe',
  matched: [{ field: 'process.command_line', value_preview: 'powershell -enc' }],
  ...recurrence,
});

describe('Hits of a hunt run', () => {
  it('should tell the new hits from the ones seen before, and tag each sampled hit', () => {
    testRender(
      <HuntRunHits
        hitsCount={120}
        newCount={12}
        recurringCount={108}
        identified
        windowContinued
        platform="Splunk prod"
        hits={[hit(1, { is_new: true }), hit(2, { is_new: false, times_seen: 4, known_since: '2026-10-01T10:00:00Z' })]}
      />,
    );
    expect(screen.getByTestId('hunt-run-hits-breakdown')).toHaveTextContent('120 (12 new, 108 seen before)');
    expect(screen.getByTestId('hunt-run-window-continued')).toHaveTextContent('Searched since the previous run on Splunk prod, with a 15-minute overlap');
    const tags = screen.getAllByTestId('hunt-run-hit-recurrence');
    expect(tags[0]).toHaveTextContent('New');
    // A short date keeps the tag inside its column; the exact date and time are in its tooltip, reachable by keyboard
    expect(tags[1]).toHaveTextContent('Seen 4 times since Oct 1, 2026');
    const trigger = screen.getByTestId('hunt-run-hit-recurrence-trigger');
    expect(trigger).toHaveAttribute('tabindex', '0');
    expect(trigger).toContainElement(tags[1]);
    // The focus ring of the design system, not the outline of the browser
    expect(trigger).toHaveClass('focus-visible:outline-none', 'focus-visible:ring-2', 'focus-visible:ring-filigran-brand-primary');
    expect(screen.queryByTestId('hunt-run-hits-unidentified')).not.toBeInTheDocument();
  });

  it('should say every hit counts as new when the connector identifies none', () => {
    testRender(<HuntRunHits hitsCount={7} newCount={7} recurringCount={0} identified={false} windowContinued={false} platform="Splunk prod" hits={[hit(1)]} />);
    expect(screen.getByTestId('hunt-run-hits-breakdown')).toHaveTextContent('7 hits');
    expect(screen.getByTestId('hunt-run-hits-unidentified')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-hit-recurrence')).not.toBeInTheDocument();
  });

  it('should show the first sampled hits, then all of them on demand', () => {
    const hits = Array.from({ length: 14 }, (_, index) => hit(index, { is_new: true }));
    testRender(<HuntRunHits hitsCount={14} newCount={14} recurringCount={0} identified windowContinued={false} platform="Splunk prod" hits={hits} />);
    expect(screen.getAllByTestId('hunt-run-hit-recurrence')).toHaveLength(10);
    fireEvent.click(screen.getByTestId('hunt-run-hits-toggle'));
    expect(screen.getAllByTestId('hunt-run-hit-recurrence')).toHaveLength(14);
  });
});
