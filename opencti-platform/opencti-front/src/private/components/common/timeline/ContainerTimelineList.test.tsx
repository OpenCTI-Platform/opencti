import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineList, { type TimelineListEvent } from './ContainerTimelineList';

const CONTEXT = 'Global first and last seen of the entity, context only: not dated in this incident';

const seen = (id: string, kind: string): TimelineListEvent => ({
  id,
  title: `Event ${id}`,
  event_time: '2026-02-05T10:00:00.000Z',
  event_end_time: '2026-02-20T00:00:00.000Z',
  lane: 'adversary',
  kind,
  rule_id: 'entity-first-last-seen',
  precision: 'exact',
  pinned: false,
  hidden: false,
  source: 'derived',
});

describe('ContainerTimelineList context windows', () => {
  it('says under the title of the global first and last seen of an entity that it is context only', () => {
    testRender(<ContainerTimelineList events={[seen('malware-1', 'malware_seen'), seen('incident-1', 'incident_seen')]} grouping="day" canEdit={false} onSelect={vi.fn()} />);
    const context = screen.getByTestId('timeline-list-event-malware-1');
    expect(within(context).getByTestId('timeline-list-event-context')).toHaveTextContent(CONTEXT);
    expect(context.getAttribute('aria-label')).toContain(CONTEXT);
    // The first and last seen of the incident itself date this incident
    const dated = screen.getByTestId('timeline-list-event-incident-1');
    expect(within(dated).queryByTestId('timeline-list-event-context')).not.toBeInTheDocument();
    expect(dated.getAttribute('aria-label')).not.toContain(CONTEXT);
  });
});
