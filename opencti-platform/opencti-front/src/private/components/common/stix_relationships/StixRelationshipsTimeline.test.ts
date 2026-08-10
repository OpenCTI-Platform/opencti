import { describe, expect, it } from 'vitest';
import type { WidgetDataSelection } from '../../../../utils/widget/widget';
import {
  buildStixRelationshipsTimelineData,
  RELATIONSHIP_TIMELINE_DATE_KEY,
} from './StixRelationshipsTimeline';

describe('buildStixRelationshipsTimelineData', () => {
  it('uses relationship date attribute on relDate without overriding remote node created field', () => {
    const selection = {
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'fromId',
            values: ['from-1'],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      },
      isTo: true,
    } as unknown as WidgetDataSelection;

    const timelineData = buildStixRelationshipsTimelineData(
      [
        {
          node: {
            id: 'rel-1',
            created: '2024-01-01T00:00:00.000Z',
            created_at: '2024-02-01T00:00:00.000Z',
            from: {
              id: 'from-1',
              entity_type: 'Threat-Actor',
              created: '2023-01-01T00:00:00.000Z',
            },
            to: {
              id: 'to-1',
              entity_type: 'Malware',
              created: '2020-01-01T00:00:00.000Z',
            },
          },
        },
      ] as unknown as Parameters<typeof buildStixRelationshipsTimelineData>[0],
      selection,
      'created_at',
    );

    expect(timelineData).toHaveLength(1);
    expect(timelineData[0]?.value.id).toBe('to-1');
    expect(timelineData[0]?.value.created).toBe('2020-01-01T00:00:00.000Z');
    expect(timelineData[0]?.value[RELATIONSHIP_TIMELINE_DATE_KEY]).toBe('2024-02-01T00:00:00.000Z');
  });

  it('supports non-created relationship date attributes (e.g. start_time)', () => {
    const selection = {
      filters: { filters: [{ key: 'fromId', values: ['from-1'] }] },
      isTo: true,
    } as unknown as WidgetDataSelection;

    const timelineData = buildStixRelationshipsTimelineData(
      [
        {
          node: {
            id: 'rel-1',
            created: '2024-01-01T00:00:00.000Z',
            created_at: '2024-02-01T00:00:00.000Z',
            start_time: '2024-03-01T00:00:00.000Z',
            from: { id: 'from-1', entity_type: 'Threat-Actor' },
            to: { id: 'to-1', entity_type: 'Malware' },
          },
        },
      ] as unknown as Parameters<typeof buildStixRelationshipsTimelineData>[0],
      selection,
      'start_time',
    );

    expect(timelineData).toHaveLength(1);
    expect(timelineData[0]?.value[RELATIONSHIP_TIMELINE_DATE_KEY]).toBe('2024-03-01T00:00:00.000Z');
  });
});
