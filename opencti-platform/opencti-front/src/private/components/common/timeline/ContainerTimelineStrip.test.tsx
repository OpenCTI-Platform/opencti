import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import type { OperationDescriptor } from 'relay-runtime';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineStrip from './ContainerTimelineStrip';
import { TIMELINE_DEFAULT_HEADLINE_DATES, type TimelineAnchorKey } from './timelineUtils';

// Headline dates of the type, set in Settings > Customization
const headlineDates = vi.hoisted(() => ({ current: [] as readonly string[] }));
vi.mock('./useTimelineHeadlineDates', () => ({ default: () => headlineDates.current }));

const NO_ANCHORS = {
  first_adversary_activity: null,
  first_detection: null,
  first_response: null,
  containment: null,
  eradication: null,
  recovery: null,
  notification: null,
  closure: null,
};
let anchors: Record<TimelineAnchorKey, string | null> = NO_ANCHORS;

beforeEach(() => {
  headlineDates.current = TIMELINE_DEFAULT_HEADLINE_DATES;
  anchors = NO_ANCHORS;
});

interface StripCase {
  canEdit?: boolean;
  enabledLanes?: string[];
  hiddenKinds?: string[];
}

// The summary of the case counts every event, the events query only the lanes and kinds its timeline settings show
const renderStrip = async (total: number, shownEvents: Array<Record<string, unknown>>, { canEdit = true, enabledLanes = ['adversary'], hiddenKinds = [] }: StripCase = {}) => {
  const rendered = testRender(<ContainerTimelineStrip containerId="case-1" entityType="Case-Incident" basePath="/dashboard/cases/incidents/case-1" />);
  const { relayEnv } = rendered;
  const resolve = (operation: OperationDescriptor) => {
    if (operation.request.node.params.name === 'ContainerTimelineStripQuery') {
      return {
        data: {
          containerTimelineSummary: {
            total,
            first_event_time: total > 0 ? '2026-02-01T09:00:00.000Z' : null,
            last_event_time: total > 0 ? '2026-02-03T09:00:00.000Z' : null,
            can_edit: canEdit,
            anchors,
            settings: { id: 'timeline-settings-1', enabled_lanes: enabledLanes, hidden_kinds: hiddenKinds, default_grouping: 'day' },
          },
        },
      };
    }
    return {
      data: {
        shown: {
          total: shownEvents.length,
          first_event_time: shownEvents.length > 0 ? '2026-02-02T09:00:00.000Z' : null,
          last_event_time: shownEvents.length > 0 ? '2026-02-02T09:00:00.000Z' : null,
        },
        containerTimeline: { edges: shownEvents.map((node) => ({ node })) },
      },
    };
  };
  await waitFor(() => relayEnv.mock.resolveMostRecentOperation(resolve));
  if (total > 0) {
    await waitFor(() => relayEnv.mock.resolveMostRecentOperation(resolve));
  }
  return rendered;
};

const stripEvent = (id: string, title: string, time: string) => ({
  id,
  event_time: time,
  event_end_time: null,
  precision: 'exact',
  lane: 'adversary',
  kind: 'technique_used',
  rule_id: 'technique-kill-chain',
  title,
  pinned: false,
  hidden: false,
  source: 'derived',
  annotation: null,
});

describe('ContainerTimelineStrip', () => {
  it('explains what fills a new timeline and offers editors to add a milestone', async () => {
    await renderStrip(0, []);
    expect(await screen.findByTestId('timeline-strip-empty')).toHaveTextContent('The timeline fills itself from the knowledge of the case and the milestones you add.');
    expect(screen.getByRole('button', { name: 'Add a milestone' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Timeline settings' })).toBeNull();
  });

  it('points to the timeline settings when they hide every event of the case', async () => {
    await renderStrip(4, []);
    expect(await screen.findByTestId('timeline-strip-empty')).toHaveTextContent('The timeline settings hide every event of the case (lanes switched off or events hidden by default). Change the settings from the Timeline tab.');
    expect(screen.getByRole('button', { name: 'Timeline settings' })).toBeInTheDocument();
    expect(screen.queryByTestId('timeline-strip-summary')).toBeNull();
  });

  it('offers a milestone next to the settings only when the settings would show it', async () => {
    await renderStrip(4, [], { enabledLanes: ['adversary'] });
    await screen.findByTestId('timeline-strip-empty');
    expect(screen.queryByRole('button', { name: 'Add a milestone' })).toBeNull();
  });

  it('keeps a new milestone as the secondary step when its lane and kind are shown', async () => {
    await renderStrip(4, [], { enabledLanes: ['response'], hiddenKinds: ['technique_used'] });
    await screen.findByTestId('timeline-strip-empty');
    expect(screen.getByRole('button', { name: 'Timeline settings' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add a milestone' })).toBeInTheDocument();
  });

  it('tells readers why the card is empty without offering a change they cannot make', async () => {
    await renderStrip(4, [], { canEdit: false });
    const empty = await screen.findByTestId('timeline-strip-empty');
    expect(empty).toHaveTextContent('The timeline settings hide every event of the case (lanes switched off or events hidden by default).');
    expect(empty).not.toHaveTextContent('Change the settings');
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('counts the events the timeline settings show', async () => {
    await renderStrip(4, [{
      id: 'event-1',
      event_time: '2026-02-02T09:00:00.000Z',
      event_end_time: null,
      precision: 'exact',
      lane: 'adversary',
      kind: 'technique_used',
      title: 'Technique Phishing',
      pinned: false,
      hidden: false,
      source: 'derived',
      annotation: null,
    }]);
    expect(await screen.findByTestId('timeline-strip-summary')).toHaveTextContent('1 event');
    expect(screen.queryByTestId('timeline-strip-empty')).toBeNull();
  });

  it('lists the headline dates of the type only, in their order', async () => {
    headlineDates.current = ['containment', 'recovery', 'closure'];
    anchors = { ...NO_ANCHORS, first_detection: '2026-02-01T10:00:00.000Z', recovery: '2026-02-03T08:00:00.000Z' };
    await renderStrip(1, [stripEvent('event-1', 'Technique Phishing', '2026-02-02T09:00:00.000Z')]);
    const list = await screen.findByTestId('timeline-anchors');
    expect(within(list).getAllByRole('listitem').map((item) => item.getAttribute('data-testid'))).toEqual([
      'timeline-anchor-containment',
      'timeline-anchor-recovery',
      'timeline-anchor-closure',
    ]);
    // A date the type does not show is left out even when it is reached
    expect(screen.queryByTestId('timeline-anchor-first_detection')).toBeNull();
    expect(screen.getByTestId('timeline-anchor-recovery')).not.toHaveTextContent('Not reached');
  });

  it('lists the events of a numbered circle, each opening the Timeline tab on that event', async () => {
    const { user } = await renderStrip(2, [
      stripEvent('event-2', 'Technique Exfiltration', '2026-02-02T11:00:00.000Z'),
      stripEvent('event-1', 'Technique Phishing', '2026-02-02T09:00:00.000Z'),
    ]);
    await user.click(await screen.findByRole('button', { name: /^2 events - / }));
    const items = await screen.findAllByRole('menuitem');
    expect(items.map((item) => item.textContent)).toEqual([
      expect.stringContaining('Technique Phishing'),
      expect.stringContaining('Technique Exfiltration'),
    ]);
    expect(items[0]).toHaveTextContent('Technique used');
    await user.click(items[1]);
    await waitFor(() => expect(`${window.location.pathname}${window.location.search}`).toBe('/dashboard/cases/incidents/case-1/timeline?event=event-2'));
  });
});
