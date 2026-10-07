import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import type { OperationDescriptor } from 'relay-runtime';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineStrip from './ContainerTimelineStrip';

const NO_ANCHORS = { first_adversary_activity: null, first_detection: null, first_response: null, containment: null, closure: null };

interface StripCase {
  canEdit?: boolean;
  enabledLanes?: string[];
  hiddenKinds?: string[];
}

// The summary of the case counts every event, the events query only the lanes and kinds its timeline settings show
const renderStrip = async (total: number, shownEvents: Array<Record<string, unknown>>, { canEdit = true, enabledLanes = ['adversary'], hiddenKinds = [] }: StripCase = {}) => {
  const { relayEnv } = testRender(<ContainerTimelineStrip containerId="case-1" basePath="/dashboard/cases/incidents/case-1" />);
  const resolve = (operation: OperationDescriptor) => {
    if (operation.request.node.params.name === 'ContainerTimelineStripQuery') {
      return {
        data: {
          containerTimelineSummary: {
            total,
            first_event_time: total > 0 ? '2026-02-01T09:00:00.000Z' : null,
            last_event_time: total > 0 ? '2026-02-03T09:00:00.000Z' : null,
            can_edit: canEdit,
            anchors: NO_ANCHORS,
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
};

describe('ContainerTimelineStrip', () => {
  it('explains what fills a new timeline and offers editors to add a milestone', async () => {
    await renderStrip(0, []);
    expect(await screen.findByTestId('timeline-strip-empty')).toHaveTextContent('The timeline fills itself from the knowledge of the case and the milestones you add.');
    expect(screen.getByRole('button', { name: 'Add a milestone' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Timeline settings' })).toBeNull();
  });

  it('points to the timeline settings when they hide every event of the case', async () => {
    await renderStrip(4, []);
    expect(await screen.findByTestId('timeline-strip-empty')).toHaveTextContent('Every event of the case is in a lane or a kind the timeline settings hide. Change the settings from the Timeline tab.');
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
    expect(empty).toHaveTextContent('Every event of the case is in a lane or a kind the timeline settings hide.');
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
});
