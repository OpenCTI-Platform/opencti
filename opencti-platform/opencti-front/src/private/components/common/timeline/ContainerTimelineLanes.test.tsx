import React from 'react';
import { describe, expect, it, vi } from 'vitest';
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

describe('ContainerTimelineLanes accessibility', () => {
  const domain: [number, number] = [new Date('2026-02-01T00:00:00.000Z').getTime(), new Date('2026-02-10T00:00:00.000Z').getTime()];

  it('is an image when nothing in it can be activated', () => {
    renderLanes([event('derived-1', 'derived')]);
    expect(screen.getByRole('img', { name: 'Timeline' })).toBeInTheDocument();
  });

  it('is a group exposing its events as buttons when they can be opened', () => {
    testRender(
      <ContainerTimelineLanes
        events={[event('derived-1', 'derived')]}
        lanes={['response']}
        domain={domain}
        grouping="day"
        ariaLabel="Timeline"
        onSelect={() => {}}
      />,
    );
    expect(screen.queryByRole('img', { name: 'Timeline' })).toBeNull();
    expect(screen.getByRole('group', { name: 'Timeline' })).toBeInTheDocument();
    expect(screen.getByTestId('timeline-event-derived-1')).toHaveAttribute('role', 'button');
  });

  it('draws a focus ring around a cluster, shown on keyboard focus only', () => {
    const { container } = testRender(
      <ContainerTimelineLanes
        events={[event('derived-1', 'derived'), event('derived-2', 'derived')]}
        lanes={['response']}
        domain={domain}
        grouping="day"
        ariaLabel="Timeline"
        onClusterSelect={() => {}}
      />,
    );
    const cluster = screen.getByRole('button', { name: /^2 events - / });
    expect(cluster).toHaveAttribute('tabindex', '0');
    expect(cluster.querySelector('.timeline-cluster-focus')).not.toBeNull();
    expect(container.querySelector('style')?.textContent).toMatch(/\.timeline-cluster:focus-visible \.timeline-cluster-focus[^{]*\{ visibility: visible; \}/);
  });

  it('keeps a cluster of the visible events on screen when the middle of its bucket is not, and zooms on its events', () => {
    // Zoomed on the afternoon of a day: the middle of the day bucket (noon) is off screen, two of its events are on it
    const at = (id: string, time: string) => ({ ...event(id, 'derived'), event_time: time });
    const onClusterSelect = vi.fn();
    testRender(
      <ContainerTimelineLanes
        events={[at('morning', '2026-02-05T08:00:00.000Z'), at('afternoon-1', '2026-02-05T15:00:00.000Z'), at('afternoon-2', '2026-02-05T16:00:00.000Z')]}
        lanes={['response']}
        domain={[new Date('2026-02-05T14:00:00.000Z').getTime(), new Date('2026-02-05T18:00:00.000Z').getTime()]}
        grouping="day"
        ariaLabel="Timeline"
        onClusterSelect={onClusterSelect}
      />,
    );
    // The event before the window is left out of the count
    const cluster = screen.getByRole('button', { name: /^2 events - / });
    fireEvent.click(cluster);
    expect(onClusterSelect).toHaveBeenCalledWith([new Date('2026-02-05T15:00:00.000Z').getTime(), new Date('2026-02-05T16:00:00.000Z').getTime()]);
  });

  it('draws a focus ring around an event that can be opened, shown on keyboard focus only', () => {
    const { container } = testRender(
      <ContainerTimelineLanes
        events={[event('derived-1', 'derived')]}
        lanes={['response']}
        domain={domain}
        grouping="day"
        ariaLabel="Timeline"
        onSelect={() => {}}
      />,
    );
    const marker = screen.getByTestId('timeline-event-derived-1');
    expect(marker).toHaveAttribute('tabindex', '0');
    expect(marker).toHaveClass('timeline-event');
    expect(marker.querySelector('.timeline-event-focus')).not.toBeNull();
    expect(container.querySelector('style')?.textContent).toMatch(/\.timeline-event:focus-visible \.timeline-event-focus[^{]*\{ visibility: visible; \}/);
  });

  it('outlines the zoomable chart on keyboard focus only, never with an inline style that would hide it', () => {
    const { container } = testRender(
      <ContainerTimelineLanes
        events={[event('derived-1', 'derived')]}
        lanes={['response']}
        domain={domain}
        grouping="day"
        ariaLabel="Timeline"
        onDomainChange={() => {}}
      />,
    );
    const chart = screen.getByTestId('timeline-lanes');
    expect(chart).toHaveAttribute('tabindex', '0');
    expect(chart).toHaveClass('timeline-lanes');
    expect(chart.style.outline).toEqual('');
    expect(container.querySelector('style')?.textContent).toMatch(/\.timeline-lanes:focus-visible \{ outline: 2px solid [^;]+; outline-offset: -2px; \}/);
  });
});
