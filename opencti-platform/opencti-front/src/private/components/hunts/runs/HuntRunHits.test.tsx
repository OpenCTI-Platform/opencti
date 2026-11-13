import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import HuntRunHits, { type HuntRunHit } from './HuntRunHits';

// The data table reads the metrics and the links of the platform, which the application provides
vi.mock('../../../../utils/hooks/useAppData', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../utils/hooks/useAppData')>();
  return { ...original, useAppData: () => ({ metricsDefinition: [], computeLink: () => undefined }), useComputeLink: () => () => undefined };
});

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
  // The table keeps its sort in the local storage of the run
  afterEach(() => localStorage.clear());

  it('should tell the new hits from the ones seen before, and tag each sampled hit', () => {
    testRender(
      <HuntRunHits
        runId="run-1"
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
    // Two hits of 120 are kept: the card says so
    expect(screen.getByTestId('hunt-run-hits-sampled')).toHaveTextContent('2 of 120 hits are kept as a sample');
  });

  it('should say nothing of a sample that holds every hit', () => {
    testRender(<HuntRunHits runId="run-1" hitsCount={2} newCount={2} recurringCount={0} identified windowContinued={false} platform="Splunk prod" hits={[hit(1), hit(2)]} />);
    expect(screen.queryByTestId('hunt-run-hits-sampled')).not.toBeInTheDocument();
  });

  it('should say every hit counts as new when the connector identifies none', () => {
    testRender(<HuntRunHits runId="run-1" hitsCount={7} newCount={7} recurringCount={0} identified={false} windowContinued={false} platform="Splunk prod" hits={[hit(1)]} />);
    expect(screen.getByTestId('hunt-run-hits-breakdown')).toHaveTextContent('7 hits');
    expect(screen.getByTestId('hunt-run-hits-unidentified')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-hit-recurrence')).not.toBeInTheDocument();
  });

  it('should show the most recent sampled hits first, then all of them on demand', () => {
    // The hit of index 13 is the most recent
    const hits = Array.from({ length: 14 }, (_, index) => hit(index, { is_new: true, timestamp: `2026-10-05T${String(index + 5).padStart(2, '0')}:00:00Z` }));
    testRender(<HuntRunHits runId="run-1" hitsCount={14} newCount={14} recurringCount={0} identified windowContinued={false} platform="Splunk prod" hits={hits} />);
    const hosts = () => within(screen.getByTestId('hunt-run-hits')).getAllByRole('row').map((row) => within(row).getAllByRole('gridcell')[1].textContent);
    expect(hosts()).toEqual(['ws-13', 'ws-12', 'ws-11', 'ws-10', 'ws-9', 'ws-8', 'ws-7', 'ws-6', 'ws-5', 'ws-4']);
    expect(screen.getAllByTestId('hunt-run-hit-recurrence')).toHaveLength(10);
    fireEvent.click(screen.getByTestId('hunt-run-hits-toggle'));
    expect(screen.getAllByTestId('hunt-run-hit-recurrence')).toHaveLength(14);
    expect(hosts().slice(-1)).toEqual(['ws-0']);
  });

  it('should show the process of a hit that matched no value', () => {
    testRender(<HuntRunHits runId="run-1" hitsCount={1} newCount={1} recurringCount={0} identified windowContinued={false} platform="Splunk prod" hits={[hit(1, { matched: [] })]} />);
    const [cells] = within(screen.getByTestId('hunt-run-hits')).getAllByRole('row').map((row) => within(row).getAllByRole('gridcell').map((cell) => cell.textContent));
    expect(cells.slice(1, 5)).toEqual(['ws-1', 'jdoe', '', 'powershell.exe']);
  });
});
