import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineLanes, { type TimelineChartEvent } from './ContainerTimelineLanes';

const event = (id: string, source: string): TimelineChartEvent => ({
  id,
  title: `Event ${id}`,
  event_time: '2026-02-05T10:00:00.000Z',
  lane: 'response',
  kind: 'note',
  precision: 'exact',
  pinned: false,
  hidden: false,
  source,
});

const renderLanes = (events: TimelineChartEvent[]) => testRender(
  <ContainerTimelineLanes
    events={events}
    lanes={['response']}
    domain={[new Date('2026-02-01T00:00:00.000Z').getTime(), new Date('2026-02-10T00:00:00.000Z').getTime()]}
    grouping="day"
    ariaLabel="Timeline"
  />,
);

describe('ContainerTimelineLanes tooltip', () => {
  it('tells where a derived event comes from', () => {
    renderLanes([event('derived-1', 'derived')]);
    fireEvent.mouseEnter(screen.getByTestId('timeline-event-derived-1'));
    expect(screen.getByRole('tooltip')).toHaveTextContent('Event derived-1');
    expect(screen.getByTestId('timeline-tooltip-source')).toHaveTextContent('Derived from the knowledge');
  });

  it('tells that a milestone was added by an analyst', () => {
    renderLanes([event('manual-1', 'manual')]);
    fireEvent.mouseEnter(screen.getByTestId('timeline-event-manual-1'));
    expect(screen.getByTestId('timeline-tooltip-source')).toHaveTextContent('Analyst milestone');
  });
});
