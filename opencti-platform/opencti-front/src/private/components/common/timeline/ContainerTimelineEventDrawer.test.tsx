import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ContainerTimelineEventDrawer, { type TimelineEventDetails } from './ContainerTimelineEventDrawer';

vi.mock('../../../../utils/hooks/useAppData', () => ({
  useComputeLink: () => () => '/dashboard/observations/indicators/indicator-1',
}));

// A SHA-256 hash: the name of an indicator is often its IOC value
const HASH = 'bb23545380fde9f4b9f6a8bd1f6d3c7e2a3b4c5d6e7f8091a2b3c4d5681d8c4e';

const indicatorEvent: TimelineEventDetails = {
  id: 'event-1',
  title: `Indicator validity: ${HASH}`,
  event_time: '2026-03-01T00:00:00.000Z',
  event_end_time: '2026-06-01T00:00:00.000Z',
  lane: 'evidence',
  kind: 'indicator_valid',
  precision: 'exact',
  pinned: false,
  hidden: false,
  source: 'derived',
  editable: false,
  analyst_fields: [],
  objectMarking: [{ id: 'marking-1', definition: 'TLP:CLEAR', definition_type: 'TLP', x_opencti_order: 0, x_opencti_color: '#ffffff' }],
  element: { id: 'indicator-1', entity_type: 'Indicator', representative: { main: HASH } },
};

const renderDrawer = (event: TimelineEventDetails) => testRender(
  <ContainerTimelineEventDrawer
    event={event}
    canEdit={false}
    onClose={vi.fn()}
    onTogglePin={vi.fn()}
    onToggleHide={vi.fn()}
    onSaveAnnotation={vi.fn()}
    onEdit={vi.fn()}
    onDelete={vi.fn()}
    onCenter={vi.fn()}
  />,
  { userContext: createMockUserContext() },
);

describe('ContainerTimelineEventDrawer with a long indicator value', () => {
  it('crops the hash in the title so the whole title stays visible', () => {
    renderDrawer(indicatorEvent);
    expect(screen.getByText('Indicator validity: bb235453...681d8c4e')).toBeInTheDocument();
    expect(screen.queryByText(`Indicator validity: ${HASH}`)).not.toBeInTheDocument();
  });

  it('keeps the full hash in the Element field, wrapped inside its column', () => {
    renderDrawer(indicatorEvent);
    expect(screen.getByTestId('timeline-event-element')).toHaveTextContent(HASH);
    expect(screen.getByTestId('timeline-event-element-value')).toHaveStyle({ overflowWrap: 'anywhere', minWidth: '0' });
  });

  it('leaves the titles made of ordinary words untouched', () => {
    renderDrawer({ ...indicatorEvent, title: 'Indicator validity: malicious domain of the phishing campaign' });
    expect(screen.getByText('Indicator validity: malicious domain of the phishing campaign')).toBeInTheDocument();
  });
});

describe('ContainerTimelineEventDrawer source', () => {
  it('names the attributes and the entity the dates of a derived event come from', () => {
    renderDrawer({ ...indicatorEvent, rule_id: 'indicator-validity', element: { ...indicatorEvent.element, representative: { main: 'jiaw.shop' } } });
    expect(screen.getByTestId('timeline-event-source')).toHaveTextContent('Taken from the Valid from and Valid until of the indicator jiaw.shop');
  });

  it('says that a technique without a dated relationship is placed by kill chain order', () => {
    renderDrawer({
      ...indicatorEvent,
      title: 'Technique Phishing',
      kind: 'technique_used',
      lane: 'adversary',
      precision: 'approximate',
      event_end_time: null,
      rule_id: 'technique-kill-chain',
      element: { id: 'attack-pattern-1', entity_type: 'Attack-Pattern', representative: { main: 'Phishing' } },
    });
    expect(screen.getByTestId('timeline-event-source')).toHaveTextContent('Placed by kill chain order: this technique has no dated relationship');
  });
});

describe('ContainerTimelineEventDrawer element', () => {
  it('names the element as the timeline does: a note without an abstract by the start of its content', () => {
    renderDrawer({
      ...indicatorEvent,
      title: 'Note The encrypted shares are mounted from FS-FIN-02 only',
      kind: 'note_added',
      lane: 'response',
      event_end_time: null,
      element_name: 'The encrypted shares are mounted from FS-FIN-02 only',
      element: { id: 'note-1', entity_type: 'Note', representative: { main: 'Unknown' } },
    });
    expect(screen.getByTestId('timeline-event-element')).toHaveTextContent('The encrypted shares are mounted from FS-FIN-02 only');
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
  });
});

describe('ContainerTimelineEventDrawer context windows', () => {
  const malwareSeen: TimelineEventDetails = {
    ...indicatorEvent,
    title: 'Malware LockBit seen',
    kind: 'malware_seen',
    lane: 'adversary',
    rule_id: 'entity-first-last-seen',
    element: { id: 'malware-1', entity_type: 'Malware', representative: { main: 'LockBit' } },
  };

  it('says under Time that the global first and last seen of an entity are context only', () => {
    renderDrawer(malwareSeen);
    expect(screen.getByTestId('timeline-event-context')).toHaveTextContent('Global first and last seen of the entity, context only: not dated in this incident');
  });

  it('shows no context caption for an event dated in this incident', () => {
    renderDrawer(indicatorEvent);
    expect(screen.queryByTestId('timeline-event-context')).not.toBeInTheDocument();
    renderDrawer({ ...malwareSeen, kind: 'incident_seen' });
    expect(screen.queryByTestId('timeline-event-context')).not.toBeInTheDocument();
  });
});
